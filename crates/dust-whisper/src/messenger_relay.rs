//! In-memory messenger inbox on the DUST Whisper relay.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::RngCore;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::protocol::{
    MESSENGER_ACK_PATH, MESSENGER_CHALLENGE_PATH, MESSENGER_INBOX_PATH, MESSENGER_SEND_PATH,
    MessengerAckRequest, MessengerAckResponse, MessengerChallengeResponse, MessengerEnvelope,
    MessengerInboxRequest, MessengerInboxResponse, MessengerSendRequest, MessengerSendResponse,
};

const MAX_PER_RECIPIENT: usize = 200;
/// How many undelivered envelopes one sender may hold in one recipient's inbox.
///
/// Eviction used to be "drop the oldest entry in the list", so a flood of junk
/// deleted the genuine mail that had been waiting longest. Senders are
/// authenticated now, so the inbox can charge each of them for its own share.
///
/// What that share does and does not buy. A flood from ONE identity costs only
/// itself, held by `a_flood_from_one_key_evicts_only_its_own_messages` in
/// `tests/messenger_inbox_flood.rs`.
///
/// A flood from MANY identities used to defeat this entirely: keys are free, and
/// eviction took from whichever sender held the most slots, which after a wide
/// flood of one-shot identities is the genuine correspondent. That is closed by
/// the refusal below rather than by this cap - a sender holding nothing in a
/// full inbox cannot displace what is already there
/// (`a_flood_from_many_keys_cannot_evict_the_genuine_correspondent`, same file).
///
/// A share can also be spent by somebody who holds no key at all, which is what
/// `MAX_AGE_PAST` and the duplicate-id refusal below are for: a stranger who
/// copied one genuine envelope off an unencrypted hop used to be able to post it
/// twenty times, and because the replay carries the real sender's real
/// signature, every copy was charged to the real sender and evicted twenty of
/// their genuine messages. See `a_replayed_envelope_cannot_delete_the_senders_mail`.
const MAX_PER_SENDER: usize = 20;
const TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// Ceiling on outstanding challenges across the whole relay.
///
/// Challenges are keyed by their own nonce rather than by address. Keyed by
/// address there was exactly one slot per person and anybody could overwrite
/// it, which silently locked the owner out of their own inbox for as long as
/// the attacker kept asking. Keyed by nonce there is nothing to aim at.
///
/// Reaching this ceiling used to make `issue_challenge` hand an EMPTY nonce to
/// everybody, and an empty nonce never verifies, so 8320 unauthenticated GETs
/// locked every honest owner out of every inbox on the relay at once, and
/// holding it there cost about 68 requests a second. Filling the table now
/// evicts the OLDEST outstanding challenge instead of refusing the newest
/// caller, so a full table denies nobody: a wallet asks for a challenge and
/// spends it in the same round trip, and its entry is the newest one there.
///
/// What that leaves, stated rather than hidden: an attacker who can insert
/// `MAX_PENDING_CHALLENGES` entries inside one victim's round trip can still
/// evict that victim's fresh challenge, and the wallet reports it as a relay
/// that refused the claim. That is a race against a specific person at a very
/// high request rate, not a switch that turns the whole relay off, and rate
/// limiting in the reverse proxy is what removes it (docs/RUNNING-A-RELAY.md).
///
/// There is deliberately no per-address cap here. Bounding by address puts the
/// target back: a stranger asking repeatedly for somebody else's address would
/// evict the challenge that person was about to spend, which is the lockout
/// `a_stranger_requesting_challenges_cannot_empty_the_owners_inbox` exists to
/// forbid.
const MAX_PENDING_CHALLENGES: usize = 8192;
/// Largest ciphertext, in hex characters, that one envelope may carry.
///
/// The only previous bound was the router's 512 KiB body limit, so one sender
/// with one key could park hundreds of megabytes on somebody else's machine.
/// A chat message is small; 16 KiB of ciphertext is roughly a 16,000-character
/// message, which is far more than the wallet will send (`MAX_MESSAGE_BODY_BYTES`
/// in `wallet-core/src/messenger.rs` is 4 KiB).
const MAX_CIPHERTEXT_HEX: usize = 32 * 1024;
/// How many distinct inboxes the relay will hold mail for at once.
const MAX_INBOXES: usize = 5_000;
/// How many undelivered envelopes the relay will hold in total.
const MAX_TOTAL_ENVELOPES: usize = 20_000;
/// Total stored envelope bytes the relay will hold.
///
/// `to` used to be a free string, so a single key could invent inboxes without
/// limit and the per-sender share multiplied instead of binding. `to` has to be
/// a claimable Hacash address now, and these three ceilings put an absolute
/// bound on what one machine can be made to hold: nothing here is ever deleted
/// to make room, the relay refuses instead and says so.
const MAX_TOTAL_BYTES: usize = 48 * 1024 * 1024;
/// How far in the past an envelope's signed `sent_at` may be.
///
/// `sent_at` is inside `envelope_auth_digest`, so nobody but the sender can
/// choose it. That makes this a replay window rather than a formality: a
/// stranger who copied an envelope off the wire can only re-post it while it is
/// still fresh, and while it is fresh the duplicate-id refusal below is almost
/// always what answers them.
const MAX_AGE_PAST_SECS: i64 = 30 * 60;
/// How far ahead of the relay's own clock an envelope may claim to be, so that
/// an honest sender whose clock is a little fast is not refused.
const MAX_SKEW_FUTURE_SECS: i64 = 5 * 60;

#[derive(Clone)]
struct Stored {
    envelope: MessengerEnvelope,
    received: Instant,
}

#[derive(Clone)]
struct Challenge {
    to: String,
    issued: Instant,
    expires: Instant,
}

/// Every inbox on the relay, with the two totals that bound the whole store.
///
/// The counters are maintained rather than recomputed: recomputing over the
/// whole map on each push would make a flood cost the relay more than it costs
/// the flooder.
#[derive(Default)]
struct Inboxes {
    map: HashMap<String, Vec<Stored>>,
    envelopes: usize,
    bytes: usize,
}

fn stored_size(env: &MessengerEnvelope) -> usize {
    env.id.len()
        + env.to.len()
        + env.from.len()
        + env.from_pubkey.as_deref().map_or(0, str::len)
        + env.from_sig.as_deref().map_or(0, str::len)
        + env.nonce.len()
        + env.ciphertext.len()
        + env.sent_at.len()
}

impl Inboxes {
    /// Drop expired entries from one inbox and keep the totals honest.
    fn prune(&mut self, to: &str) {
        let Some(list) = self.map.get_mut(to) else {
            return;
        };
        let mut dropped = 0usize;
        let mut freed = 0usize;
        list.retain(|s| {
            let keep = s.received.elapsed() < TTL;
            if !keep {
                dropped += 1;
                freed += stored_size(&s.envelope);
            }
            keep
        });
        self.envelopes = self.envelopes.saturating_sub(dropped);
        self.bytes = self.bytes.saturating_sub(freed);
        if list.is_empty() {
            self.map.remove(to);
        }
    }

    fn remove_at(&mut self, to: &str, idx: usize) {
        if let Some(list) = self.map.get_mut(to)
            && idx < list.len()
        {
            let gone = list.remove(idx);
            self.envelopes = self.envelopes.saturating_sub(1);
            self.bytes = self.bytes.saturating_sub(stored_size(&gone.envelope));
        }
    }

    fn insert(&mut self, to: String, envelope: MessengerEnvelope) {
        self.envelopes += 1;
        self.bytes += stored_size(&envelope);
        self.map.entry(to).or_default().push(Stored {
            envelope,
            received: Instant::now(),
        });
    }

    fn list(&self, to: &str) -> &[Stored] {
        self.map.get(to).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[derive(Clone, Default)]
pub struct MessengerInbox {
    inner: Arc<Mutex<Inboxes>>,
    /// Nonce -> the address it was issued for. Never keyed by address.
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
}

/// True when this string is an address a key could ever sign for.
///
/// Collecting mail means signing the relay's challenge with the secp256k1 key
/// that derives to the claimed address, so only a version-0 (PRIVAKEY) address
/// has an inbox anybody can ever empty. `to` used to be any non-empty string at
/// all: a sender could invent inboxes by the thousand, none of them claimable
/// by anyone, and nothing in the relay ever pruned them.
fn is_claimable_address(addr: &str) -> bool {
    field::Address::from_readable(addr).is_ok_and(|a| a.is_privakey())
}

/// The envelope's own signed timestamp, against the relay's clock.
fn check_freshness(sent_at: &str, now: DateTime<Utc>) -> Result<(), String> {
    let Ok(claimed) = DateTime::parse_from_rfc3339(sent_at.trim()) else {
        return Err("envelope timestamp is not an RFC3339 time".into());
    };
    let age = now
        .signed_duration_since(claimed.with_timezone(&Utc))
        .num_seconds();
    if age > MAX_AGE_PAST_SECS {
        return Err(
            "envelope timestamp is older than this relay accepts. If this was not a replay, \
             check the sending machine's clock"
                .into(),
        );
    }
    if age < -MAX_SKEW_FUTURE_SECS {
        return Err(
            "envelope timestamp is ahead of this relay's clock. Check the sending machine's clock"
                .into(),
        );
    }
    Ok(())
}

impl MessengerInbox {
    pub fn new() -> Self {
        Self::default()
    }

    async fn push(&self, envelope: MessengerEnvelope) -> Result<(), String> {
        let to = envelope.to.trim().to_string();
        if to.is_empty() {
            return Err("missing recipient".into());
        }
        if !is_claimable_address(&to) {
            return Err(
                "recipient is not a Hacash account address, so no key could ever collect it".into(),
            );
        }
        if envelope.ciphertext.len() > MAX_CIPHERTEXT_HEX {
            return Err("envelope body is larger than this relay accepts".into());
        }
        check_freshness(&envelope.sent_at, Utc::now())?;
        let from = envelope.from.trim().to_string();
        let size = stored_size(&envelope);

        let mut inboxes = self.inner.lock().await;
        inboxes.prune(&to);

        // Before any eviction decision, because a duplicate must never be
        // allowed to cost anybody a slot. A replayed envelope carries the real
        // sender's real signature, so eviction charged it to them: twenty
        // replays of one captured envelope deleted twenty genuine messages.
        if inboxes
            .list(&to)
            .iter()
            .any(|s| s.envelope.id == envelope.id)
        {
            return Err("this relay already holds an envelope with that id".into());
        }

        let list_len = inboxes.list(&to).len();
        let from_this_sender = inboxes
            .list(&to)
            .iter()
            .filter(|s| s.envelope.from.trim() == from)
            .count();
        if from_this_sender >= MAX_PER_SENDER {
            // This sender is already using its whole share. Drop its own oldest
            // entry rather than somebody else's.
            if let Some(idx) = inboxes
                .list(&to)
                .iter()
                .position(|s| s.envelope.from.trim() == from)
            {
                inboxes.remove_at(&to, idx);
            }
        } else if list_len >= MAX_PER_RECIPIENT && from_this_sender == 0 {
            // The inbox is full and this sender holds nothing in it yet, so
            // there is no share to charge and nothing here is theirs to take.
            //
            // Refusing is the whole defence against a flood spread across
            // throwaway keys. Evicting instead would take from the sender
            // holding the most slots, and once every flooder holds one, that is
            // the person the owner actually talks to: the flood would delete
            // the correspondent and keep itself. Keys are free, so any rule
            // that lets a brand new sender displace stored mail is a rule an
            // attacker can buy for nothing.
            //
            // The cost of refusing is real and is the honest trade: a genuine
            // NEW correspondent cannot reach an inbox that is already full. It
            // fills only when the owner has not collected for a while, and
            // collection empties it, so that is a delay. Deleting the person
            // they talk to is not.
            return Err("inbox full".into());
        } else if list_len >= MAX_PER_RECIPIENT {
            // The inbox is full of other people's mail. Evict from whichever
            // sender is taking up the most room, oldest of theirs first. That
            // charges a single loud sender for its own noise. It does NOT
            // protect a real correspondent from a flood spread across many
            // throwaway keys: once every flooder holds one slot, the sender
            // holding the most is the person the owner actually talks to, and
            // this branch deletes them first. See MAX_PER_SENDER above.
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for s in inboxes.list(&to) {
                *counts.entry(s.envelope.from.trim()).or_default() += 1;
            }
            let Some((&worst, _)) = counts.iter().max_by_key(|&(_, &n)| n) else {
                return Err("inbox full".into());
            };
            let worst = worst.to_string();
            if let Some(idx) = inboxes
                .list(&to)
                .iter()
                .position(|s| s.envelope.from.trim() == worst)
            {
                inboxes.remove_at(&to, idx);
            }
        }

        // What the whole machine will hold, checked after any eviction so a
        // replacement is not refused for the room it is about to free. Nothing
        // here deletes to make space: a relay that is full says so.
        let new_inbox = !inboxes.map.contains_key(&to);
        if new_inbox && inboxes.map.len() >= MAX_INBOXES {
            return Err("this relay is holding all the mailboxes it will hold".into());
        }
        if inboxes.envelopes >= MAX_TOTAL_ENVELOPES || inboxes.bytes + size > MAX_TOTAL_BYTES {
            return Err("this relay is full".into());
        }

        inboxes.insert(to, envelope);
        Ok(())
    }

    async fn issue_challenge(&self, to: &str) -> MessengerChallengeResponse {
        let mut nonce_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);
        let expires_at =
            (Utc::now() + ChronoDuration::seconds(CHALLENGE_TTL.as_secs() as i64)).to_rfc3339();
        let mut map = self.challenges.lock().await;
        let now = Instant::now();
        map.retain(|_, ch| ch.expires > now);

        // A full table evicts its oldest entry rather than refusing the caller.
        // Refusing meant one outsider could lock every owner on the relay out
        // of their own inbox with unauthenticated GETs; evicting means an
        // attacker has to out-run the honest wallet inside its own round trip.
        while map.len() >= MAX_PENDING_CHALLENGES {
            let Some(oldest) = map
                .iter()
                .min_by_key(|(_, ch)| ch.issued)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            map.remove(&oldest);
        }

        map.insert(
            nonce.clone(),
            Challenge {
                to: to.to_string(),
                issued: now,
                expires: now + CHALLENGE_TTL,
            },
        );
        MessengerChallengeResponse { nonce, expires_at }
    }

    async fn consume_challenge(&self, to: &str, nonce: &str) -> bool {
        if nonce.is_empty() {
            return false;
        }
        let mut map = self.challenges.lock().await;
        let Some(ch) = map.get(nonce) else {
            return false;
        };
        if ch.expires < Instant::now() || ch.to != to {
            return false;
        }
        map.remove(nonce);
        true
    }

    async fn peek(&self, to: &str) -> Vec<MessengerEnvelope> {
        let mut inboxes = self.inner.lock().await;
        inboxes.prune(to);
        inboxes
            .list(to)
            .iter()
            .map(|s| s.envelope.clone())
            .collect()
    }

    async fn ack(&self, to: &str, ids: &[String]) -> u32 {
        let mut inboxes = self.inner.lock().await;
        inboxes.prune(to);
        let mut removed = 0u32;
        // One at a time, so the byte and envelope totals stay right. An empty
        // id list still means "everything", as it always has.
        while let Some(idx) = inboxes
            .list(to)
            .iter()
            .position(|s| ids.is_empty() || ids.contains(&s.envelope.id))
        {
            inboxes.remove_at(to, idx);
            removed += 1;
        }
        if inboxes.list(to).is_empty() {
            inboxes.map.remove(to);
        }
        removed
    }
}

#[derive(Clone)]
pub struct RelayAppState {
    pub relay: Arc<crate::relay::RelayState>,
    pub inbox: Arc<MessengerInbox>,
}

#[derive(Deserialize)]
struct ChallengeQuery {
    to: String,
}

pub fn messenger_routes() -> Router<RelayAppState> {
    Router::new()
        .route(MESSENGER_SEND_PATH, post(send_handler))
        .route(MESSENGER_CHALLENGE_PATH, get(challenge_handler))
        .route(MESSENGER_INBOX_PATH, post(inbox_handler))
        .route(MESSENGER_ACK_PATH, post(ack_handler))
}

async fn send_handler(
    State(state): State<RelayAppState>,
    Json(req): Json<MessengerSendRequest>,
) -> Json<MessengerSendResponse> {
    // The door messages come IN through. Without this check `from` is a string
    // anybody can write, and the recipient's wallet files the result as a
    // message from whoever it names.
    if !crate::messenger_auth::verify_envelope_sender(&req.envelope) {
        return Json(MessengerSendResponse {
            ok: false,
            err: Some("envelope is not signed by the key its sender address derives from".into()),
        });
    }
    match state.inbox.push(req.envelope).await {
        Ok(()) => Json(MessengerSendResponse {
            ok: true,
            err: None,
        }),
        Err(e) => Json(MessengerSendResponse {
            ok: false,
            err: Some(e),
        }),
    }
}

async fn challenge_handler(
    State(state): State<RelayAppState>,
    Query(q): Query<ChallengeQuery>,
) -> Json<MessengerChallengeResponse> {
    let to = q.to.trim();
    // An address no key can sign for never gets a challenge, so the table
    // cannot be filled with invented names.
    if to.is_empty() || !is_claimable_address(to) {
        return Json(MessengerChallengeResponse {
            nonce: String::new(),
            expires_at: Utc::now().to_rfc3339(),
        });
    }
    Json(state.inbox.issue_challenge(to).await)
}

async fn inbox_handler(
    State(state): State<RelayAppState>,
    Json(req): Json<MessengerInboxRequest>,
) -> Json<MessengerInboxResponse> {
    let to = req.to.trim();
    let refused = || {
        Json(MessengerInboxResponse {
            messages: Vec::new(),
            auth_ok: false,
        })
    };
    if to.is_empty() {
        return refused();
    }
    // Signature first, nonce second. Consuming the nonce before checking who
    // sent it meant any caller could burn the challenge the owner was about to
    // use, and the owner's own correctly signed fetch then came back empty.
    if !crate::messenger_auth::verify_inbox_auth(
        to,
        req.nonce.trim(),
        &req.claimant_pubkey,
        &req.signature,
    ) {
        return refused();
    }
    if !state.inbox.consume_challenge(to, req.nonce.trim()).await {
        return refused();
    }
    let messages = state.inbox.peek(to).await;
    Json(MessengerInboxResponse {
        messages,
        auth_ok: true,
    })
}

async fn ack_handler(
    State(state): State<RelayAppState>,
    Json(req): Json<MessengerAckRequest>,
) -> Json<MessengerAckResponse> {
    let to = req.to.trim();
    if to.is_empty() {
        return Json(MessengerAckResponse {
            ok: false,
            removed: 0,
            err: Some("missing recipient".into()),
        });
    }
    // Same order as the inbox handler, for the same reason: a caller who cannot
    // sign for this address must not be able to spend its challenge.
    if !crate::messenger_auth::verify_inbox_auth(
        to,
        req.nonce.trim(),
        &req.claimant_pubkey,
        &req.signature,
    ) {
        return Json(MessengerAckResponse {
            ok: false,
            removed: 0,
            err: Some("invalid inbox auth signature".into()),
        });
    }
    if !state.inbox.consume_challenge(to, req.nonce.trim()).await {
        return Json(MessengerAckResponse {
            ok: false,
            removed: 0,
            err: Some("invalid or expired challenge".into()),
        });
    }
    let removed = state.inbox.ack(to, &req.ids).await;
    Json(MessengerAckResponse {
        ok: true,
        removed,
        err: None,
    })
}
