//! Encrypted wallet-to-wallet chat via DUST Whisper relay + encrypted local history.

use std::fs;
use std::time::{Duration, Instant};

use chrono::Utc;
use dust_whisper::protocol::{MessengerAckRequest, MessengerEnvelope, MessengerInboxRequest};
use serde::{Deserialize, Serialize};
use sys::Account;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::account::WalletAccount;
use crate::error::{WalletError, WalletResult};
use crate::messenger_crypto::{
    EnvelopeBinding, MESSENGER_CRYPTO_V1, MESSENGER_CRYPTO_V2, decrypt_body, decrypt_store,
    encrypt_body_v1, encrypt_body_v2, encrypt_store, parse_pubkey_hex, pubkey_hex, sign_inbox_auth,
    storage_key_from_secret, verified_peer_pubkey,
};
use crate::paths::{messenger_path, secure_write};

/// The longest message body this wallet will send, or accept off a relay.
///
/// There was no bound at all in either direction. A 1 MiB body was accepted by
/// `messenger_send` and stored; inbound, one keypair could add 8.8 MiB to the
/// local store per poll cycle, forever, and both shells rendered the newest body
/// raw into the conversation list. A chat message is not a file transfer.
pub const MAX_MESSAGE_BODY_BYTES: usize = 4096;
/// How many messages the encrypted local store will hold.
///
/// The store is one file, decrypted and rewritten in full on every poll, and it
/// had no ceiling. This one is deliberately a refusal rather than an eviction:
/// dropping the oldest to make room would let anybody who can post to an inbox
/// delete a conversation by filling it, which is the same mistake the relay's
/// inbox cap already had to be talked out of. Messages the store has no room for
/// are left on the relay, and the poll says so.
const MAX_STORED_MESSAGES: usize = 10_000;
/// The whole of what a peer-key lookup may spend before the send goes ahead
/// without one.
///
/// The lookup runs in front of a person pressing Send, and it runs on exactly
/// the case this wallet cannot avoid: a first message, where nothing is known
/// about the peer and nothing is learned if the answer does not come. Left on
/// the shared client's 20 second per-request budget, three relays that accept a
/// connection and never reply cost a minute, on that message and on every one
/// after it until the peer writes back. Running out here is not a failure: it
/// is the v1 fallback the sender was on before this existed, marked not sealed.
const PEER_KEY_LOOKUP_BUDGET: Duration = Duration::from_secs(6);
/// The most any one relay may take to answer the lookup.
///
/// A directory answer is a hash lookup and 66 characters of hex. A relay that
/// cannot produce that quickly is not going to produce it usefully, and one
/// slow or deliberately stalling entry in a list must not eat the budget the
/// rest of the list needs.
const PEER_KEY_RELAY_TIMEOUT: Duration = Duration::from_secs(3);
/// How much of a message the conversation list is given for its preview line.
///
/// Both shells render `last_message` straight into the thread row, so without
/// this a single very long body is a very long row.
const THREAD_PREVIEW_CHARS: usize = 160;

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
    /// When this wallet actually took delivery of an inbound message.
    ///
    /// `timestamp_utc` is the sender's own signed claim, and a relay that holds
    /// a message back for a week still delivers that claim untouched. The
    /// conversation used to be ordered on it alone, so a held message landed in
    /// the middle of the history, did not move the thread to the top of the
    /// list, and rendered as a clock time with no date. This is the wallet's own
    /// clock, and it is what the conversation is ordered on. `None` on outgoing
    /// messages, and on records written before the wallet kept it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_utc: Option<String>,
    /// Why no relay took an outgoing message, in the relay's own words.
    ///
    /// `delivered: false` was the whole story, so "the relay is down" and "that
    /// person's mailbox is full" arrived at the screen as the same sentence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_error: Option<String>,
    /// WHICH relay took it. `None` when none did, and on records written
    /// before this field existed.
    ///
    /// A send stops at the first relay in the list that accepts, and a wallet
    /// hosting its own relay always has one that accepts: its own, on this
    /// machine. So a person whose list reads `[my own relay, my friend's]`
    /// delivered every message into their own mailbox, where the friend cannot
    /// collect it, and `delivered: true` with no error was the whole of what
    /// the screen was given. Polling tries EVERY relay, so the friend's replies
    /// still arrived and the thread looked like a conversation.
    ///
    /// Naming the relay is what makes that visible. The screen prints it, and
    /// compares it against the relay this wallet is itself hosting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_via: Option<String>,
}

impl ChatMessage {
    /// The wallet's own clock where it has one, the sender's claim otherwise.
    ///
    /// Ordering on this rather than on `timestamp_utc` is what stops a relay
    /// choosing where in a conversation a message it held appears.
    pub fn ordering_key(&self) -> &str {
        self.received_utc.as_deref().unwrap_or(&self.timestamp_utc)
    }
}

/// What the screen is allowed to say about one conversation's privacy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessengerPeerSecurity {
    /// This wallet already holds a verified key for the peer, so the next send
    /// is v2 without asking anybody anything.
    ///
    /// `false` no longer means the next send cannot be sealed: it means this
    /// wallet holds nothing yet, and `messenger_send` will ask the configured
    /// relays for a key and check it against the peer's own address before
    /// using it (`lookup_peer_key`). This is read without touching the network,
    /// so it cannot say how that will go. It errs to `false`, which is the
    /// direction that cannot turn into a claim the crypto did not make; the
    /// per-message `sealed` flag is what records what actually happened, and it
    /// is set from the version that was really used.
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
    /// Envelopes the wallet refused to believe: no verifiable sender, or
    /// addressed to somebody else entirely and handed over anyway.
    pub rejected_envelopes: u32,
    /// Envelopes correctly signed by a real key whose body this wallet could
    /// not open, discarded from the relay rather than left there.
    ///
    /// Leaving them was a way to shut an inbox permanently: 200 signed
    /// envelopes of noise, and the poll skipped each one without acking it, so
    /// they were never removed, the inbox stayed at the relay's per-recipient
    /// cap, every established correspondent was refused with "inbox full", and
    /// the owner's own polls reported a clean empty mailbox.
    pub undecryptable: u32,
    /// The local store was already at its ceiling, so messages were left on the
    /// relay rather than taken. Not an empty inbox, and not a failure to reach
    /// one either.
    pub store_full: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatThread {
    pub peer: String,
    /// The newest message in the thread, cut to `THREAD_PREVIEW_CHARS`.
    pub last_message: String,
    /// The sender's own claim about when the newest message was written.
    pub last_timestamp_utc: String,
    /// When this wallet last saw activity in the thread, by its own clock.
    ///
    /// The list is ordered on this. Ordered on the sender's claim, a relay
    /// holding a message back kept the thread out of sight at the bottom of the
    /// list when it finally released it.
    #[serde(default)]
    pub last_activity_utc: String,
    pub unread: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MessengerStore {
    messages: Vec<ChatMessage>,
    /// Peer address -> compressed secp256k1 pubkey hex, kept only after the key
    /// derives back to that address. Without it a send has nothing to seal
    /// against and falls back to v1, whose key is the two public addresses and
    /// therefore no secret at all.
    ///
    /// Two things fill this in, and they are held to the same check. An inbound
    /// envelope addressed to this wallet carries its sender's key
    /// (`learn_peer_key` in the poll), and a relay asked before a send can serve
    /// the last key it saw for an address (`lookup_peer_key`). Neither source is
    /// trusted: an address is the hash of its key, so a key that derives to the
    /// address is that address's key no matter who handed it over, and one that
    /// does not is discarded.
    #[serde(default)]
    peer_keys: std::collections::BTreeMap<String, String>,
}

/// The conversation-list preview of one body: whole if short, cut if not.
fn preview(body: &str) -> String {
    if body.chars().count() <= THREAD_PREVIEW_CHARS {
        return body.to_string();
    }
    let mut out: String = body.chars().take(THREAD_PREVIEW_CHARS).collect();
    out.push_str("...");
    out
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
                last_activity_utc: String::new(),
                unread: 0,
            });
            if m.ordering_key() >= entry.last_activity_utc.as_str() {
                entry.last_message = preview(&m.body);
                entry.last_timestamp_utc = m.timestamp_utc.clone();
                entry.last_activity_utc = m.ordering_key().to_string();
            }
            if m.direction == MessageDirection::In && !m.delivered {
                entry.unread += 1;
            }
        }
        let mut out: Vec<_> = map.into_values().collect();
        out.sort_by(|a, b| b.last_activity_utc.cmp(&a.last_activity_utc));
        out
    }

    pub fn messages_for(&self, peer: &str) -> Vec<ChatMessage> {
        let mut out: Vec<_> = self
            .messages
            .iter()
            .filter(|m| m.peer == peer)
            .cloned()
            .collect();
        // The wallet's own clock, not the sender's claim. See
        // `ChatMessage::ordering_key`.
        out.sort_by(|a, b| a.ordering_key().cmp(b.ordering_key()));
        out
    }

    /// Take a message into the store, or refuse because it is full.
    ///
    /// Refusing rather than evicting is deliberate: see `MAX_STORED_MESSAGES`.
    fn is_full(&self) -> bool {
        self.messages.len() >= MAX_STORED_MESSAGES
    }

    #[must_use]
    fn push(&mut self, msg: ChatMessage) -> bool {
        if self.is_full() {
            return false;
        }
        self.messages.push(msg);
        true
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
        let Some(parsed) = verified_peer_pubkey(pubkey_hex_str, peer) else {
            return false;
        };
        let normalized = hex::encode(parsed);
        if self.peer_keys.get(peer) == Some(&normalized) {
            return false;
        }
        self.peer_keys.insert(peer.to_string(), normalized);
        true
    }

    /// Re-checked on the way out, not only on the way in. A store file is a
    /// file on a disk; the derivation is cheap and the guarantee is that
    /// nothing is ever sealed to a key this wallet has not just verified.
    fn peer_key(&self, peer: &str) -> Option<[u8; 33]> {
        verified_peer_pubkey(self.peer_keys.get(peer)?, peer)
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
    id: &str,
    peer_pubkey: Option<&[u8; 33]>,
) -> WalletResult<(u8, String, String, Option<String>)> {
    // The body is sealed against the envelope it will travel in, so the same
    // bytes cannot be lifted into any other envelope. See `EnvelopeBinding`.
    if let Some(peer_pk) = peer_pubkey {
        let binding = EnvelopeBinding {
            id,
            from: ctx.my_address,
            to: peer,
            v: MESSENGER_CRYPTO_V2,
        };
        let (nonce, ciphertext) = encrypt_body_v2(
            ctx.account,
            ctx.my_address,
            peer,
            peer_pk,
            body,
            sent_at,
            &binding,
        )?;
        Ok((
            MESSENGER_CRYPTO_V2,
            nonce,
            ciphertext,
            Some(pubkey_hex(ctx.account)),
        ))
    } else {
        let binding = EnvelopeBinding {
            id,
            from: ctx.my_address,
            to: peer,
            v: MESSENGER_CRYPTO_V1,
        };
        let (nonce, ciphertext) = encrypt_body_v1(ctx.my_address, peer, body, sent_at, &binding);
        Ok((
            MESSENGER_CRYPTO_V1,
            nonce,
            ciphertext,
            Some(pubkey_hex(ctx.account)),
        ))
    }
}

/// Ask the configured relays for a key for `peer`, and verify every answer.
///
/// # The gap this closes
///
/// Until the other person had written back, a sender held no key of theirs, so
/// `encrypt_for_send` fell back to v1, whose key is `SHA256(domain || the two
/// addresses)` and both addresses are printed in clear on the envelope. The
/// relay operator has both. That made the FIRST message of every conversation
/// readable by whoever runs the relay, and since no screen offers a way to
/// supply a correspondent's key in advance, that is how every conversation
/// started.
///
/// # Why asking the relay is not trusting it
///
/// Every envelope already carries `from_pubkey`, so a relay has seen the public
/// key of everyone who has sent through it, and it can serve the last one it
/// saw for an address. It is not believed. `verified_peer_pubkey` re-derives
/// the address from whatever comes back and throws it away unless it matches
/// the address that was asked about, and a Hacash address IS the hash of its
/// public key, so a key that passes that check is that address's key. A hostile
/// relay's only moves are to answer nothing, or to answer something that fails
/// the check. Both return `None` here, which is exactly "this wallet holds no
/// key", which is where the sender was before this function existed: v1, and a
/// screen that says the message is not sealed.
///
/// # What it costs, in time
///
/// Two requests per configured relay, and only on a send to a
/// peer this wallet holds no key for. A relay that is down, slow or hostile
/// costs a failed request and nothing else: every arm here falls through to the
/// next relay and then to `None`.
///
/// The time that costs is bounded here rather than inherited. On the shared
/// client's 20 second per-request budget, three relays that accept a connection
/// and never answer put a full minute in front of a person pressing Send, and
/// because a lookup that finds nothing writes nothing down, that minute is paid
/// again on the next message and the one after. So the whole lookup gets
/// `PEER_KEY_LOOKUP_BUDGET`, each relay gets at most
/// `PEER_KEY_RELAY_TIMEOUT` of it, and what is left over is what the next relay
/// may spend. Running out of budget is the same outcome as a relay with no key:
/// v1, and a screen that says so.
///
/// # What it costs, in metadata
///
/// This asks every configured relay until one answers with a key that checks
/// out, while the send itself stops at the first relay that accepts the
/// envelope. So a relay that never carries the message can still be told the
/// recipient's address. That is a real disclosure to a party outside the
/// delivery path, it is stated on both shells' banner and in section 6.1 of
/// docs/RUNNING-A-RELAY.md, and it is the price of sealing an opening message
/// at all: the wallet cannot know which relay holds the key without asking, and
/// the alternative is the v1 fallback, in which the operator reads the message
/// itself and learns the same address from the envelope a moment later.
///
/// It is kept as small as it can be. The question is a POST, so the address
/// does not land in an access log, and the loop stops at the first relay whose
/// answer survives checking rather than polling them all.
///
/// # Why it now says who is asking
///
/// The relay's key directory used to answer anybody, and its answer differed by
/// whether the address asked about was on that relay's list. That made it a
/// membership test a passer-by could run. It answers a listed caller only now,
/// so this fetches a challenge for THIS wallet's own address first and signs
/// it - the same credential the inbox poll already presents, to the same relay.
/// A relay this wallet is not listed on hands back a decoy nonce, the signed
/// request is refused, and the answer is `None`: the same outcome as a relay
/// that never had a key, and the same honest v1 fallback.
async fn lookup_peer_key(
    http: &reqwest::Client,
    account: &Account,
    my_address: &str,
    relay_urls: &[String],
    peer: &str,
) -> Option<[u8; 33]> {
    let deadline = Instant::now() + PEER_KEY_LOOKUP_BUDGET;
    let asker_pubkey = pubkey_hex(account);
    for url in relay_urls {
        let u = url.trim();
        if u.is_empty() {
            continue;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            // The budget is spent. Stop asking rather than let a stalled relay
            // list hold a send open; this is the same outcome as no answer.
            break;
        }
        let budget = left.min(PEER_KEY_RELAY_TIMEOUT);
        // The credential this relay wants, obtained from this relay. A relay
        // that will not issue this wallet a real nonce is a relay that will not
        // answer the question either, and both end at `continue`.
        let challenge = match tokio::time::timeout(
            budget,
            dust_whisper::messenger_client::fetch_challenge(http, u, my_address),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(_)) | Err(_) => continue,
        };
        let signature = sign_inbox_auth(account, my_address, &challenge.nonce);
        let asker = dust_whisper::messenger_client::PubkeyAsker {
            address: my_address,
            pubkey_hex: &asker_pubkey,
            nonce: &challenge.nonce,
            signature: &signature,
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let budget = left.min(PEER_KEY_RELAY_TIMEOUT);
        let claimed =
            match dust_whisper::messenger_client::fetch_peer_pubkey(http, u, peer, &asker, budget)
                .await
            {
                Ok(Some(claimed)) => claimed,
                // No key, no answer at all, or no answer in time. All are "ask
                // the next one", and if there is no next one, all are the
                // honest v1 fallback.
                Ok(None) | Err(_) => continue,
            };
        // The check that makes the whole thing safe. A wrong answer is treated
        // as no answer, and the next relay is asked, rather than the send being
        // failed or - far worse - the answer being used.
        if let Some(verified) = verified_peer_pubkey(&claimed, peer) {
            return Some(verified);
        }
    }
    None
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
    if trimmed.len() > MAX_MESSAGE_BODY_BYTES {
        return Err(WalletError::Other(format!(
            "a message can be at most {MAX_MESSAGE_BODY_BYTES} bytes. This one is {}",
            trimmed.len()
        )));
    }
    let ctx = messenger_ctx(account, my_address);
    let sent_at = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();
    // The store is loaded before the body is sealed, not after it is sent: it
    // is where this wallet keeps the peer keys it has learned, and a key here
    // is the difference between ECDH (v2) and a "key" the relay already has
    // both halves of (v1).
    let mut store = MessengerStore::load(&ctx)?;
    // Checked before the envelope is built, so nothing is sent that this wallet
    // has no room to remember sending.
    if store.is_full() {
        return Err(WalletError::Other(format!(
            "this wallet's message store is full ({MAX_STORED_MESSAGES} messages), so nothing \
             was sent. Nothing here deletes messages for you"
        )));
    }
    let mut peer_pk = match peer_pubkey_hex {
        // A key handed in by a caller is checked against the address here, the
        // same way a relay's answer is, rather than being parsed and left for
        // `encrypt_body_v2` to refuse further down. No shipped screen passes
        // this yet; when one does, the rule that nothing is sealed to an
        // unverified key is already enforced at the point the key enters.
        Some(hex_str) => Some(verified_peer_pubkey(hex_str, peer).ok_or_else(|| {
            WalletError::Other(
                "that public key does not belong to this address, so nothing was sent. A Hacash \
                 address is the hash of its own public key, and this one does not hash to it"
                    .into(),
            )
        })?),
        None => store.peer_key(peer),
    };
    // Nothing of theirs on hand, which used to mean the opening message of the
    // conversation travelled v1 and the relay operator read it. Ask the relays
    // for the key they have already seen this address send with, and use it
    // only if it derives back to this address. See `lookup_peer_key`.
    if peer_pk.is_none()
        && let Some(found) = lookup_peer_key(http, ctx.account, my_address, relay_urls, peer).await
    {
        // Kept, so the screen's banner catches up with what the send actually
        // did and the next message does not ask again. `learn_peer_key`
        // verifies once more before it writes anything down.
        store.learn_peer_key(peer, &hex::encode(found));
        peer_pk = Some(found);
    }
    let (crypto_v, nonce, ciphertext, from_pubkey) =
        encrypt_for_send(&ctx, peer, trimmed, &sent_at, &id, peer_pk.as_ref())?;

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

    // WHICH relay took it, not merely whether one did. The loop below stops at
    // the first relay that accepts, and a wallet hosting its own relay has one
    // that always accepts, so "a relay accepted it" was true of a message that
    // had gone no further than this machine. See `ChatMessage::delivered_via`.
    let mut accepted_by: Option<String> = None;
    // Kept, because "no relay accepted this" and "that person's mailbox is
    // full" are different facts and used to reach the screen as one sentence.
    let mut refusal: Option<String> = None;
    for url in relay_urls {
        let u = url.trim();
        if u.is_empty() {
            continue;
        }
        match dust_whisper::messenger_client::send_envelope(http, u, envelope.clone()).await {
            Ok(()) => {
                accepted_by = Some(u.to_string());
                break;
            }
            // A relay that answered and said no gives its own sentence, which
            // is the useful one; anything else is a transport failure and says
            // so in its own words.
            Err(dust_whisper::error::WhisperError::Relay(reason)) => refusal = Some(reason),
            Err(e) => refusal = Some(e.to_string()),
        }
    }

    let msg = ChatMessage {
        id,
        peer: peer.to_string(),
        direction: MessageDirection::Out,
        body: trimmed.to_string(),
        timestamp_utc: sent_at,
        delivered: accepted_by.is_some(),
        sealed: Some(crypto_v == MESSENGER_CRYPTO_V2),
        received_utc: None,
        delivery_error: if accepted_by.is_some() { None } else { refusal },
        delivered_via: accepted_by,
    };

    // The room was checked before anything left the machine, so this cannot
    // refuse a message that has already been handed to a relay.
    debug_assert!(!store.is_full());
    let _ = store.push(msg.clone());
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
            // Addressed to this wallet, checked rather than assumed.
            //
            // `to` was never compared with anything. A relay could serve
            // somebody else's envelope out of this inbox and the wallet would
            // learn a public key from it and report the thread with a stranger
            // as sealed, about a person who had never written. The crypto
            // covered for the body; nothing covered for that.
            if env.to.trim() != my_address {
                outcome.rejected_envelopes += 1;
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
            let binding = EnvelopeBinding {
                id: &env.id,
                from: &env.from,
                to: my_address,
                v: env.v,
            };
            let plain = match decrypt_body(
                ctx.account,
                my_address,
                &env.from,
                peer_pk.as_ref(),
                &env.nonce,
                &env.ciphertext,
                &binding,
            ) {
                Ok(p) => p,
                Err(_) => {
                    // This was the wedge, and it was one missing line. Every
                    // other skip in this loop acks; this one did not, so a
                    // correctly signed envelope of noise sat in the inbox for
                    // the relay's full seven-day TTL, was re-downloaded on
                    // every poll, was not counted anywhere, and held a slot
                    // against the relay's per-recipient cap. Two hundred of
                    // them, which is ten free keypairs, made an address deaf to
                    // everybody it already talked to while its owner was told
                    // "nothing new".
                    //
                    // What is given up by acking: an envelope in a crypto
                    // version this build does not understand is thrown away
                    // rather than waiting for a build that would. There is no
                    // such version, and a mailbox that cannot be emptied is a
                    // worse thing to ship than that risk.
                    outcome.undecryptable += 1;
                    ack_ids.push(env.id);
                    continue;
                }
            };
            if plain.body.len() > MAX_MESSAGE_BODY_BYTES {
                // Nothing this wallet sends can be this long, so nothing that
                // is came from a wallet playing by the rules.
                outcome.rejected_envelopes += 1;
                ack_ids.push(env.id);
                continue;
            }
            let taken = store.push(ChatMessage {
                id: env.id.clone(),
                peer: env.from,
                direction: MessageDirection::In,
                body: plain.body,
                timestamp_utc: plain.sent_at,
                delivered: false,
                sealed: Some(env.v == MESSENGER_CRYPTO_V2),
                // This wallet's own clock. The sender's claim is kept beside it
                // and is not what the conversation is ordered on.
                received_utc: Some(Utc::now().to_rfc3339()),
                delivery_error: None,
                // Inbound. The relay it came from is not a fact about a message
                // this wallet sent, and nothing on screen claims it is.
                delivered_via: None,
            });
            if !taken {
                // Left on the relay rather than dropped: the store is full, and
                // this is a real message somebody sent. Not acked, so it is
                // still there when there is room for it.
                outcome.store_full = true;
                continue;
            }
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
        assert!(store.push(ChatMessage {
            id: "1".into(),
            peer: "peer".into(),
            direction: MessageDirection::Out,
            body: "hi".into(),
            timestamp_utc: "t".into(),
            delivered: true,
            sealed: Some(true),
            received_utc: None,
            delivery_error: None,
            delivered_via: None,
        }));
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
        let (nonce, ciphertext) = encrypt_body_v1(
            &alice_addr,
            &bob_addr,
            "you there?",
            "2026-08-22T09:00:00Z",
            &EnvelopeBinding {
                id: "alice-opening",
                from: &alice_addr,
                to: &bob_addr,
                v: MESSENGER_CRYPTO_V1,
            },
        );
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
            &sealed.nonce,
            &sealed.ciphertext,
            &EnvelopeBinding {
                id: &sealed.id,
                from: &sealed.from,
                to: &sealed.to,
                v: MESSENGER_CRYPTO_V1,
            },
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
            &sealed.nonce,
            &sealed.ciphertext,
            &EnvelopeBinding {
                id: &sealed.id,
                from: &sealed.from,
                to: &sealed.to,
                v: sealed.v,
            },
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

    /// A relay that hands over a fixed inbox and writes down every id the
    /// wallet acks, which is the only way to see whether junk is being cleared
    /// or left behind.
    async fn spawn_acking_relay(
        messages: Vec<MessengerEnvelope>,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use axum::extract::{Query, State};
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use dust_whisper::protocol::{
            MESSENGER_ACK_PATH, MESSENGER_CHALLENGE_PATH, MESSENGER_INBOX_PATH,
            MessengerAckRequest, MessengerAckResponse, MessengerChallengeResponse,
            MessengerInboxResponse,
        };
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Recorder {
            inbox: Arc<Mutex<Vec<MessengerEnvelope>>>,
            acked: Arc<Mutex<Vec<String>>>,
        }

        let acked = Arc::new(Mutex::new(Vec::new()));
        let state = Recorder {
            inbox: Arc::new(Mutex::new(messages)),
            acked: acked.clone(),
        };
        let app = Router::new()
            .route(
                MESSENGER_CHALLENGE_PATH,
                get(|Query(_q): Query<HashMap<String, String>>| async {
                    Json(MessengerChallengeResponse {
                        nonce: "recording-relay-nonce".into(),
                        expires_at: "2099-01-01T00:00:00Z".into(),
                    })
                }),
            )
            .route(
                MESSENGER_INBOX_PATH,
                post(
                    |State(r): State<Recorder>, Json(_): Json<serde_json::Value>| async move {
                        let messages = r.inbox.lock().unwrap().clone();
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
                    |State(r): State<Recorder>, Json(req): Json<MessengerAckRequest>| async move {
                        let mut inbox = r.inbox.lock().unwrap();
                        let before = inbox.len();
                        inbox.retain(|e| !req.ids.contains(&e.id));
                        r.acked.lock().unwrap().extend(req.ids.iter().cloned());
                        Json(MessengerAckResponse {
                            ok: true,
                            removed: (before - inbox.len()) as u32,
                            err: None,
                        })
                    },
                ),
            )
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind recording relay");
        let addr = listener.local_addr().expect("recording relay address");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), handle, acked)
    }

    /// The mailbox that could not be emptied.
    ///
    /// Two hundred correctly signed envelopes of noise, which is ten free
    /// keypairs at the relay's per-sender share, and the poll's decrypt failure
    /// arm skipped each one with a bare `continue`: not acked, so never removed,
    /// re-downloaded on every poll for the relay's whole seven-day TTL, and
    /// holding the inbox at the per-recipient cap so every correspondent whose
    /// mail had already been read was refused with "inbox full". The owner's own
    /// polls reported a clean, empty mailbox, and no shipped command could
    /// clear it.
    #[tokio::test]
    async fn signed_junk_is_cleared_from_the_relay_instead_of_wedging_the_inbox() {
        let _iso = IsolatedWalletData::new();
        let bob = keyed_account("b0");
        let alice = keyed_account("a1");
        let bob_addr = bob.address();
        let alice_addr = alice.address();

        // Junk from throwaway keys: every signature real, every body noise.
        let mut inbox = Vec::new();
        for i in 0..40u32 {
            let junker =
                WalletAccount::from_secret_hex(&format!("{:0>64}", format!("{:x}", i + 3)))
                    .expect("throwaway key");
            let junker_addr = junker.address();
            inbox.push(signed_envelope(
                MessengerEnvelope {
                    v: MESSENGER_CRYPTO_V1,
                    id: format!("junk-{i}"),
                    to: bob_addr.clone(),
                    from: junker_addr,
                    from_pubkey: Some(pubkey_hex(junker.inner())),
                    from_sig: None,
                    nonce: "000102030405060708090a0b".into(),
                    ciphertext: "0123456789abcdef0123456789abcdef".into(),
                    sent_at: "2026-08-22T09:00:00Z".into(),
                },
                &junker,
            ));
        }
        // And one real message behind it, from somebody Bob talks to.
        let (nonce, ciphertext) = encrypt_body_v1(
            &alice_addr,
            &bob_addr,
            "still here",
            "2026-08-22T10:00:00Z",
            &EnvelopeBinding {
                id: "alice-real",
                from: &alice_addr,
                to: &bob_addr,
                v: MESSENGER_CRYPTO_V1,
            },
        );
        inbox.push(signed_envelope(
            MessengerEnvelope {
                v: MESSENGER_CRYPTO_V1,
                id: "alice-real".into(),
                to: bob_addr.clone(),
                from: alice_addr.clone(),
                from_pubkey: Some(pubkey_hex(alice.inner())),
                from_sig: None,
                nonce,
                ciphertext,
                sent_at: "2026-08-22T10:00:00Z".into(),
            },
            &alice,
        ));

        let (url, relay, acked) = spawn_acking_relay(inbox).await;
        let http = reqwest::Client::new();
        let outcome = messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .expect("the poll completes");

        assert_eq!(outcome.added, 1, "the real message behind the junk arrived");
        assert_eq!(
            outcome.undecryptable, 40,
            "the junk has to be counted, or the screen says 'nothing new' about a wedged inbox"
        );
        let acked_ids = acked.lock().unwrap().clone();
        for i in 0..40u32 {
            assert!(
                acked_ids.contains(&format!("junk-{i}")),
                "junk-{i} was left on the relay, which is what holds the inbox shut"
            );
        }

        // The second poll is the proof: nothing is still sitting there.
        let again = messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .expect("the second poll completes");
        relay.abort();
        assert_eq!(
            (again.added, again.undecryptable, again.rejected_envelopes),
            (0, 0, 0),
            "the inbox was not actually emptied: {again:?}"
        );
    }

    /// Somebody else's mail, handed over as if it were yours.
    ///
    /// `env.to` was never compared with anything. A relay could serve an
    /// envelope addressed to a third party out of this inbox, and the wallet
    /// learned a public key from it before it ever tried to read it. The screen
    /// then told the owner their conversation with that third party was sealed,
    /// about somebody who had never written to them.
    #[tokio::test]
    async fn an_envelope_addressed_to_somebody_else_teaches_this_wallet_nothing() {
        let _iso = IsolatedWalletData::new();
        let bob = keyed_account("b0");
        let carol = keyed_account("c3");
        let dave = keyed_account("d4");
        let bob_addr = bob.address();
        let carol_addr = carol.address();
        let dave_addr = dave.address();

        let (nonce, ciphertext) = encrypt_body_v1(
            &carol_addr,
            &dave_addr,
            "addressed to Dave, not to Bob",
            "2026-08-22T09:00:00Z",
            &EnvelopeBinding {
                id: "misaddressed-1",
                from: &carol_addr,
                to: &dave_addr,
                v: MESSENGER_CRYPTO_V1,
            },
        );
        let not_for_bob = signed_envelope(
            MessengerEnvelope {
                v: MESSENGER_CRYPTO_V1,
                id: "misaddressed-1".into(),
                to: dave_addr.clone(),
                from: carol_addr.clone(),
                from_pubkey: Some(pubkey_hex(carol.inner())),
                from_sig: None,
                nonce,
                ciphertext,
                sent_at: "2026-08-22T09:00:00Z".into(),
            },
            &carol,
        );

        let (url, relay, acked) = spawn_acking_relay(vec![not_for_bob]).await;
        let http = reqwest::Client::new();
        let outcome = messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .expect("the poll completes");
        relay.abort();

        assert_eq!(outcome.added, 0);
        assert_eq!(
            outcome.rejected_envelopes, 1,
            "an envelope addressed to a third party must be refused, not filed"
        );
        assert!(
            !messenger_peer_security(&bob, &bob_addr, &carol_addr)
                .unwrap()
                .sends_sealed,
            "Bob's wallet learned Carol's key from an envelope Carol never sent him"
        );
        assert!(
            messenger_threads(&bob, &bob_addr).unwrap().is_empty(),
            "somebody else's envelope left a conversation behind"
        );
        assert!(
            acked
                .lock()
                .unwrap()
                .contains(&"misaddressed-1".to_string()),
            "it has to be cleared too, or it comes back on every poll forever"
        );
    }

    /// A message a relay sat on for a week, filed where it belongs.
    ///
    /// `timestamp_utc` is the sender's own signed claim and a relay that holds
    /// an envelope back delivers that claim untouched. The conversation was
    /// ordered on it alone, so a held message landed in the middle of the
    /// history rather than at the end, the thread did not move to the top of the
    /// list, and the bubble rendered a clock time with no date. Only the unread
    /// count moved.
    #[tokio::test]
    async fn a_message_the_relay_held_back_is_filed_by_when_it_arrived() {
        let _iso = IsolatedWalletData::new();
        let alice = keyed_account("a1");
        let bob = keyed_account("b0");
        let alice_addr = alice.address();
        let bob_addr = bob.address();
        let http = reqwest::Client::new();

        let envelope_at = |id: &str, body: &str, sent_at: &str| {
            let (nonce, ciphertext) = encrypt_body_v1(
                &alice_addr,
                &bob_addr,
                body,
                sent_at,
                &EnvelopeBinding {
                    id,
                    from: &alice_addr,
                    to: &bob_addr,
                    v: MESSENGER_CRYPTO_V1,
                },
            );
            signed_envelope(
                MessengerEnvelope {
                    v: MESSENGER_CRYPTO_V1,
                    id: id.into(),
                    to: bob_addr.clone(),
                    from: alice_addr.clone(),
                    from_pubkey: Some(pubkey_hex(alice.inner())),
                    from_sig: None,
                    nonce,
                    ciphertext,
                    sent_at: sent_at.into(),
                },
                &alice,
            )
        };

        // Delivered on time.
        let (url, relay, _) = spawn_acking_relay(vec![envelope_at(
            "number-two",
            "NUMBER TWO",
            "2026-08-20T12:00:00Z",
        )])
        .await;
        messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .unwrap();
        relay.abort();

        // NUMBER ONE was written first and released afterwards, which is the
        // operator's whole move.
        let (url, relay, _) = spawn_acking_relay(vec![envelope_at(
            "number-one",
            "NUMBER ONE",
            "2026-08-20T09:00:00Z",
        )])
        .await;
        messenger_poll_inbox(&http, &bob, &bob_addr, std::slice::from_ref(&url))
            .await
            .unwrap();
        relay.abort();

        let messages = messenger_messages(&bob, &bob_addr, &alice_addr).unwrap();
        let bodies: Vec<&str> = messages.iter().map(|m| m.body.as_str()).collect();
        assert_eq!(
            bodies,
            vec!["NUMBER TWO", "NUMBER ONE"],
            "a held message was filed above one that had already arrived, so nothing on \
             screen shows that it is late"
        );
        let late = messages
            .iter()
            .find(|m| m.body == "NUMBER ONE")
            .expect("the held message");
        let arrived = late
            .received_utc
            .as_deref()
            .expect("the wallet has to keep its own arrival time");
        assert!(
            arrived > late.timestamp_utc.as_str(),
            "arrival {arrived} is not after the sender's claim {}",
            late.timestamp_utc
        );

        // And the thread moves to the top of the list on arrival, which is what
        // ordering the list on the sender's claim used to prevent.
        let threads = messenger_threads(&bob, &bob_addr).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(
            threads[0].last_message, "NUMBER ONE",
            "the conversation list still shows the older message as the newest thing in it"
        );
    }

    /// Why a message did not go, in the relay's own words.
    ///
    /// `messenger_send` discarded the relay's refusal, so "my relay is down"
    /// and "that person's mailbox is being flooded" arrived at the screen as
    /// one sentence with no way to tell them apart.
    #[tokio::test]
    async fn a_relays_reason_for_refusing_a_message_reaches_the_person() {
        use axum::routing::post;
        use axum::{Json, Router};
        use dust_whisper::protocol::{MESSENGER_SEND_PATH, MessengerSendResponse};

        let _iso = IsolatedWalletData::new();
        let me = keyed_account("a1");
        let peer = keyed_account("b0").address();
        let my_address = me.address();

        let app = Router::new().route(
            MESSENGER_SEND_PATH,
            post(|| async {
                Json(MessengerSendResponse {
                    ok: false,
                    err: Some("inbox full".into()),
                })
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let relay = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let http = reqwest::Client::new();
        let sent = messenger_send(
            &http,
            &me,
            &my_address,
            &peer,
            "are you there",
            std::slice::from_ref(&url),
            None,
        )
        .await
        .expect("the message is stored locally either way");
        relay.abort();

        assert!(!sent.delivered);
        let reason = sent
            .delivery_error
            .as_deref()
            .expect("the relay said why and the wallet has to keep it");
        assert!(
            reason.contains("inbox full"),
            "the relay's own words were thrown away: {reason}"
        );
    }

    /// A chat message is not a file transfer.
    ///
    /// There was no length check in either direction: `messenger_send` took a
    /// 1 MiB body and stored it, and both shells rendered the newest body raw
    /// into the conversation list.
    #[tokio::test]
    async fn an_enormous_body_is_refused_and_a_long_one_does_not_become_the_thread_row() {
        let _iso = IsolatedWalletData::new();
        let me = keyed_account("a1");
        let peer = keyed_account("b0").address();
        let my_address = me.address();
        let http = reqwest::Client::new();
        let dead = vec!["http://127.0.0.1:1".to_string()];

        let huge = "x".repeat(MAX_MESSAGE_BODY_BYTES + 1);
        let refused = messenger_send(&http, &me, &my_address, &peer, &huge, &dead, None).await;
        assert!(
            refused.is_err(),
            "a body over the cap was accepted and stored"
        );
        assert!(
            messenger_threads(&me, &my_address).unwrap().is_empty(),
            "a refused message left a conversation behind"
        );

        let long = "y".repeat(MAX_MESSAGE_BODY_BYTES);
        messenger_send(&http, &me, &my_address, &peer, &long, &dead, None)
            .await
            .expect("a body at the cap is still a message");
        let threads = messenger_threads(&me, &my_address).unwrap();
        assert_eq!(threads.len(), 1);
        assert!(
            threads[0].last_message.chars().count() <= THREAD_PREVIEW_CHARS + 3,
            "the conversation list row is {} characters long",
            threads[0].last_message.chars().count()
        );
        assert_eq!(
            messenger_messages(&me, &my_address, &peer).unwrap()[0]
                .body
                .len(),
            MAX_MESSAGE_BODY_BYTES,
            "the preview is a preview; the message itself is kept whole"
        );
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
            &EnvelopeBinding {
                id: "forged-1",
                from: &alice_addr,
                to: &bob_addr,
                v: MESSENGER_CRYPTO_V1,
            },
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
        let (nonce, ciphertext) = encrypt_body_v1(
            &alice_addr,
            &bob_addr,
            "you there?",
            "2026-08-22T09:00:00Z",
            &EnvelopeBinding {
                id: "alice-1",
                from: &alice_addr,
                to: &bob_addr,
                v: MESSENGER_CRYPTO_V1,
            },
        );
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

    /// A relay list that never answers must not hold a person on Send.
    ///
    /// The lookup runs before the message moves and only on first contact,
    /// which is exactly the case where nothing is learned if it fails, so the
    /// wait is paid again on the next message and the one after. On the shared
    /// client's 20 second per-request budget, three relays that accept the
    /// connection and go quiet measured 60.0 seconds in review. The budget here
    /// is the whole lookup's, not one relay's, so the third relay is not even
    /// asked once the first two have spent it.
    #[tokio::test]
    async fn a_relay_list_that_never_answers_cannot_hold_a_send_open() {
        use axum::Router;
        use axum::routing::any;
        use std::sync::{Arc, Mutex};

        let asked = Arc::new(Mutex::new(0usize));
        let counter = asked.clone();
        let app = Router::new().fallback(any(move || {
            let counter = counter.clone();
            async move {
                *counter.lock().unwrap() += 1;
                tokio::time::sleep(Duration::from_secs(120)).await;
                "{}"
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let url = format!("http://{addr}");
        let relays = vec![url.clone(), url.clone(), url.clone()];

        let bob = keyed_account("b0");
        let alice = keyed_account("a0");
        let alice_address = alice.address();
        let http = reqwest::Client::new();
        let started = Instant::now();
        let found = lookup_peer_key(
            &http,
            alice.inner(),
            &alice_address,
            &relays,
            &bob.address(),
        )
        .await;
        let took = started.elapsed();
        relay.abort();

        assert!(
            found.is_none(),
            "a relay that never answered was somehow turned into a key"
        );
        assert!(
            took < PEER_KEY_LOOKUP_BUDGET + PEER_KEY_RELAY_TIMEOUT,
            "three silent relays held the send for {took:?}, against a budget of \
             {PEER_KEY_LOOKUP_BUDGET:?}"
        );
        let asked = *asked.lock().unwrap();
        assert!(
            asked < 3,
            "the budget was spent and the last relay was asked anyway ({asked} of 3 asked)"
        );
    }

    /// A key handed to `messenger_send` by a caller is checked against the
    /// address before anything is sealed or sent, not left for the encryption
    /// to refuse further down.
    ///
    /// No shipped screen passes `peer_pubkey_hex` yet. This pins the rule at
    /// the point the key enters, so wiring a screen to it later cannot quietly
    /// become a way in for an unverified key.
    #[tokio::test]
    async fn a_caller_supplied_key_for_the_wrong_address_is_refused_before_anything_is_sent() {
        let _iso = IsolatedWalletData::new();
        let alice = keyed_account("a1");
        let bob = keyed_account("b0");
        let mallory = keyed_account("cc");
        let http = reqwest::Client::new();

        // Mallory's real, on-curve, perfectly valid key - for the wrong address.
        let err = messenger_send(
            &http,
            &alice,
            &alice.address(),
            &bob.address(),
            "sealed to whom?",
            &[],
            Some(&pubkey_hex(mallory.inner())),
        )
        .await
        .expect_err("a key that does not derive to the recipient was accepted");
        assert!(
            err.to_string().contains("does not belong to this address"),
            "refused for the wrong reason: {err}"
        );
        assert!(
            messenger_messages(&alice, &alice.address(), &bob.address())
                .unwrap()
                .is_empty(),
            "a message was stored despite the send being refused"
        );

        // The honest control on the same path: Bob's own key is accepted and
        // the message is sealed.
        let sent = messenger_send(
            &http,
            &alice,
            &alice.address(),
            &bob.address(),
            "sealed to Bob",
            &[],
            Some(&pubkey_hex(bob.inner())),
        )
        .await
        .expect("the recipient's own key must be usable");
        assert_eq!(sent.sealed, Some(true));
    }
}
