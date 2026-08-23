//! In-memory messenger inbox on the DUST Whisper relay.

use std::collections::{HashMap, HashSet};
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
    MESSENGER_ACK_PATH, MESSENGER_CHALLENGE_PATH, MESSENGER_INBOX_PATH, MESSENGER_PUBKEY_PATH,
    MESSENGER_SEND_PATH, MessengerAckRequest, MessengerAckResponse, MessengerChallengeResponse,
    MessengerEnvelope, MessengerInboxRequest, MessengerInboxResponse, MessengerPubkeyRequest,
    MessengerPubkeyResponse, MessengerSendRequest, MessengerSendResponse,
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
/// How many "last key seen for this address" entries the directory will hold.
///
/// Keys are free, so a flood of throwaway senders can push honest entries out
/// of this table. That costs the flooder a signed, accepted envelope each and
/// buys nothing: an evicted entry means the relay answers "no key", which is
/// the answer it gave before this table existed, and the sending wallet falls
/// back to v1 and says on screen that the message is not sealed. There is no
/// state here whose loss can be turned into a false claim.
const MAX_DIRECTORY_ENTRIES: usize = 20_000;
/// How long the directory remembers a key after last seeing that address send.
///
/// This is not a cache lifetime, it is a retention limit. Answering "who has a
/// key for this address" tells the asker that the address has used this relay
/// (section 6.2 of docs/RUNNING-A-RELAY.md), and an entry that is never dropped
/// is that fact kept forever. A month is long enough that an ordinary
/// correspondent is still reachable sealed and short enough that a relay does
/// not accumulate a permanent roster of everyone who ever touched it.
const DIRECTORY_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
/// How many stale entries a full directory drops at once when it has to make
/// room.
///
/// Evicting exactly one per insert means an O(n) scan on every insert once the
/// table is full, which is a lever an attacker holds for the price of a signed
/// envelope. Dropping a batch pays the sort once per this many inserts instead.
/// Entries dropped early are entries the relay answers "no key" for, which is
/// the answer it gave before this table existed.
const DIRECTORY_EVICT_BATCH: usize = MAX_DIRECTORY_ENTRIES / 16;

/// How often a full store is allowed to walk every inbox looking for expired
/// mail.
///
/// `prune` only ever ran on an inbox somebody touched, so envelopes in an inbox
/// nobody polls stayed counted against `MAX_TOTAL_ENVELOPES` and
/// `MAX_TOTAL_BYTES` for ever, not merely for `TTL`. A flood spread across
/// inboxes the flooder never comes back to therefore held the whole store shut
/// permanently, and the only way out was restarting the wallet, which drops
/// every genuine undelivered message with it. Expiry now reaches those inboxes
/// too: when the store is at a ceiling, and at most this often, it sweeps the
/// whole map before it refuses anybody.
///
/// The interval is the point. A sweep is O(inboxes), so a sweep on every
/// refused send would be a walk of the table for the price of one request,
/// which is the lever the directory's read path is careful not to hand out
/// either. Once a minute makes it free to the relay and useless to aim at.
const FULL_STORE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

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
    /// When the whole map was last walked for expired mail. `None` until the
    /// store first fills. See `FULL_STORE_SWEEP_INTERVAL`.
    last_full_sweep: Option<Instant>,
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

    /// Drop expired entries from EVERY inbox, not only one somebody touched.
    ///
    /// Returns how many envelopes went. Rate limited by its only caller, which
    /// is the moment the store would otherwise refuse a send: see
    /// `FULL_STORE_SWEEP_INTERVAL` for why it is not run on every push.
    fn sweep_expired(&mut self) -> usize {
        self.sweep_expired_at(Instant::now())
    }

    /// The sweep against a clock the caller supplies.
    ///
    /// `TTL` is a week and a test process is not a week old, so a test cannot
    /// push `received` into the past: the monotonic clock has no week of
    /// history behind it to subtract from. It moves `now` forward instead,
    /// which is the same comparison from the other side.
    fn sweep_expired_at(&mut self, now: Instant) -> usize {
        let mut dropped = 0usize;
        let mut freed = 0usize;
        self.map.retain(|_, list| {
            list.retain(|s| {
                let keep = now.saturating_duration_since(s.received) < TTL;
                if !keep {
                    dropped += 1;
                    freed += stored_size(&s.envelope);
                }
                keep
            });
            !list.is_empty()
        });
        self.envelopes = self.envelopes.saturating_sub(dropped);
        self.bytes = self.bytes.saturating_sub(freed);
        self.last_full_sweep = Some(now);
        dropped
    }

    /// True when a full sweep is due. A store that is not full never sweeps,
    /// and a store that is full sweeps at most once per interval.
    fn may_sweep(&self) -> bool {
        self.may_sweep_at(Instant::now())
    }

    fn may_sweep_at(&self, now: Instant) -> bool {
        match self.last_full_sweep {
            None => true,
            Some(at) => now.saturating_duration_since(at) >= FULL_STORE_SWEEP_INTERVAL,
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

/// One address's last seen sending key, and when it was last seen.
#[derive(Clone)]
struct DirectoryEntry {
    pubkey: String,
    seen: Instant,
}

/// The addresses this relay carries mail for. Nobody else, ever.
///
/// # Why this exists, and why it denies by default
///
/// The wallet offers to bind its relay to every interface so that one friend
/// can host for another. Reaching a friend means binding somewhere reachable,
/// and a socket a friend can reach is a socket every other machine on that
/// network can reach too. So the question this type answers is not "how much
/// may a stranger do" but "may a stranger be here at all", and the answer is
/// no unless the host said otherwise about that exact address.
///
/// Nothing else works. Every other bound in this relay is a bound on volume -
/// how many envelopes one inbox holds, how many bytes one sender may park -
/// and every one of them is walked around by making more keys, because keys
/// are free and mailbox addresses are free. A stranger who can reach the port
/// can post properly signed mail to inboxes of their own until
/// `MAX_TOTAL_ENVELOPES` is reached, after which the relay refuses every send
/// including the friend's, and nothing is deleted to make room. A list of
/// addresses is the one rule a free keypair cannot buy its way past.
///
/// # What an empty list means
///
/// Nobody. Not "open", not "the LAN", not "whoever asks": an empty list is a
/// relay that carries no mail for any address at all, and a host who has not
/// named anybody is hosting for nobody. That is the default because it is the
/// only default that cannot expose somebody who never made a choice.
///
/// The wallet composes the list its own relay serves in
/// `crates/wallet-tauri-common/src/desktop_relay.rs`: the host's own address,
/// plus the addresses they typed. So an untouched wallet serves exactly one
/// person, the one sitting at it.
///
/// # The one way to serve everybody
///
/// `serving_everybody`, which nothing in the wallet calls and nothing reaches
/// by default. It exists for the operator of a deliberately public relay, who
/// asks for it by name on the command line of `dust-whisper-relay`. There is
/// no code path from "I want to message my friend" to that constructor.
///
/// # What is compared
///
/// The exact trimmed address text, against `to` and against `from`. Entries
/// are not validated: an address that is not claimable simply never matches,
/// so a typo costs the person who made it their own mail and can never widen
/// the relay. That is the direction a mistake has to fail in.
#[derive(Clone)]
pub struct InboxAllowlist(Rule);

#[derive(Clone)]
enum Rule {
    /// These addresses and no others. An empty set is nobody.
    ///
    /// Kept twice: a set to answer `allows` in one lookup, and the order the
    /// caller gave them in, because the screen quotes this list back to the
    /// person who typed it and the owner's own address is first in it.
    Only(Arc<Listed>),
    /// Everybody who can reach the socket. Only ever built by name.
    Everybody,
}

struct Listed {
    set: HashSet<String>,
    order: Vec<String>,
}

impl Default for InboxAllowlist {
    /// Nobody. See the type documentation for why this is the default.
    fn default() -> Self {
        Self(Rule::Only(Arc::new(Listed {
            set: HashSet::new(),
            order: Vec::new(),
        })))
    }
}

impl InboxAllowlist {
    /// A relay that carries mail for nobody at all.
    pub fn closed() -> Self {
        Self::default()
    }

    /// Only these addresses. Empty, or whitespace only, is `closed`.
    pub fn from_addresses<I, S>(addresses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut order: Vec<String> = Vec::new();
        for address in addresses {
            let trimmed = address.as_ref().trim().to_string();
            if !trimmed.is_empty() && !order.contains(&trimmed) {
                order.push(trimmed);
            }
        }
        let set = order.iter().cloned().collect();
        Self(Rule::Only(Arc::new(Listed { set, order })))
    }

    /// A relay for whoever can reach it, asked for by name.
    ///
    /// The wallet never calls this. It is how the operator of a public relay
    /// says out loud that a public relay is what they are running, and the
    /// only caller is the `--serve-everybody` flag on `dust-whisper-relay`.
    pub fn serving_everybody() -> Self {
        Self(Rule::Everybody)
    }

    /// True when this relay was deliberately opened to everybody.
    pub fn serves_everybody(&self) -> bool {
        matches!(self.0, Rule::Everybody)
    }

    /// True when this relay carries mail for nobody at all, which is what an
    /// untouched list means.
    pub fn serves_nobody(&self) -> bool {
        match &self.0 {
            Rule::Only(listed) => listed.set.is_empty(),
            Rule::Everybody => false,
        }
    }

    /// True when this address may use this relay at all.
    pub fn allows(&self, address: &str) -> bool {
        match &self.0 {
            Rule::Only(listed) => listed.set.contains(address.trim()),
            Rule::Everybody => true,
        }
    }

    /// How many addresses were named. Zero is nobody, unless
    /// `serves_everybody`.
    pub fn len(&self) -> usize {
        match &self.0 {
            Rule::Only(listed) => listed.set.len(),
            Rule::Everybody => 0,
        }
    }

    /// True when no address was named.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The addresses this relay is enforcing, in the order they were given.
    ///
    /// Read by the wallet's own screen through `RelayEndpointReport`, so that
    /// what a person is shown is read back off the running relay rather than
    /// recomputed beside it from settings that may have moved on. The order is
    /// preserved because the screen quotes it back in the shape it was typed,
    /// with the owner's own address first. A relay opened to everybody names
    /// nobody, because there is nobody to name.
    pub fn addresses(&self) -> Vec<String> {
        match &self.0 {
            Rule::Only(listed) => listed.order.clone(),
            Rule::Everybody => Vec::new(),
        }
    }
}

/// What a caller is told when the operator did not name them.
///
/// One sentence, and the same sentence for every refused address on every
/// path, so that a person who cannot use somebody's relay learns why from the
/// relay rather than from silence - and so that the refusal itself carries no
/// information. It does not say which end of the envelope was refused, it does
/// not say how many addresses are listed, and it is byte-identical whether the
/// address is one the operator considered and left off or one this relay has
/// never seen. The only fact it hands back is the one the caller already had:
/// they are not on it.
const NOT_ON_THE_LIST: &str = "this relay carries mail only for the addresses its operator listed, and this envelope names an address that is not one of them";

#[derive(Clone, Default)]
pub struct MessengerInbox {
    inner: Arc<Mutex<Inboxes>>,
    /// Nonce -> the address it was issued for. Never keyed by address.
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
    /// Address -> the last public key an accepted envelope from it carried.
    ///
    /// Every envelope already arrives with `from_pubkey`, and `send_handler`
    /// refuses it unless that key derives to `from` and signed the envelope, so
    /// this table is not new knowledge: it is the relay writing down something
    /// it is handed on every send and currently throws away when the envelope
    /// is collected. It exists so a wallet with nothing to seal to can ask for
    /// a key and check it, instead of sending the first message of every
    /// conversation under a key this operator can derive from the two addresses
    /// on the envelope.
    directory: Arc<Mutex<HashMap<String, DirectoryEntry>>>,
    /// Who this relay is for. Empty is nobody. See `InboxAllowlist`.
    ///
    /// Held behind a lock so the list can be changed on a running relay
    /// instead of by rebuilding one. The wallet used to rebuild: every save on
    /// the Privacy screen, and every automatic node failover, dropped the
    /// socket and built a fresh store, which silently threw away every
    /// undelivered envelope on it - including for correspondents whose
    /// listing had not changed, and including on a save that changed nothing.
    /// It also meant the list a person was shown was recomputed from settings
    /// beside the relay rather than read off it, so the two could disagree.
    /// One live list, swapped in place, removes both. See `set_allowlist`.
    allowlist: Arc<std::sync::RwLock<InboxAllowlist>>,
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

    /// An inbox that carries mail only for the addresses named.
    ///
    /// An empty list is `new()`, and `new()` is an inbox that carries mail for
    /// nobody.
    pub fn with_allowlist(allowlist: InboxAllowlist) -> Self {
        Self {
            allowlist: Arc::new(std::sync::RwLock::new(allowlist)),
            ..Self::default()
        }
    }

    /// Change who this relay is for, without dropping anybody's mail.
    ///
    /// The narrowing takes effect on the very next request: a caller removed
    /// from the list is refused from here on, on every route, and one added is
    /// served from here on. Undelivered envelopes already in the store are not
    /// touched, because they were accepted under a rule that was true when
    /// they arrived; the person they are addressed to still has to prove the
    /// address to collect them, and if they have just been removed from the
    /// list they no longer can - the mail simply expires where it lies.
    pub fn set_allowlist(&self, allowlist: InboxAllowlist) {
        match self.allowlist.write() {
            Ok(mut held) => *held = allowlist,
            // A poisoned lock means a handler panicked while reading the list.
            // The safe recovery is the closed list, never the requested one.
            Err(poisoned) => *poisoned.into_inner() = InboxAllowlist::closed(),
        }
    }

    /// Who this relay is for, right now, read off the running relay.
    pub fn allowlist(&self) -> InboxAllowlist {
        match self.allowlist.read() {
            Ok(held) => held.clone(),
            // Fail closed. A panic somewhere else must never be the thing that
            // opens this relay.
            Err(_) => InboxAllowlist::closed(),
        }
    }

    /// The one question every route asks, so there is one place it is answered.
    fn allows(&self, address: &str) -> bool {
        match self.allowlist.read() {
            Ok(held) => held.allows(address),
            Err(_) => false,
        }
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
        // Both ends, before anything is stored or counted. Checked here rather
        // than in the handler so no future caller can reach the store around
        // it. Both, and not only the sender: a relay named for two friends must
        // not become a drop box addressed to a stranger either.
        if !self.allows(&to) || !self.allows(envelope.from.trim()) {
            return Err(NOT_ON_THE_LIST.into());
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
        if (inboxes.envelopes >= MAX_TOTAL_ENVELOPES || inboxes.bytes + size > MAX_TOTAL_BYTES)
            && inboxes.may_sweep()
        {
            // Expired mail in inboxes nobody ever touches used to hold its
            // slots for ever rather than for `TTL`, because `prune` only ran on
            // an inbox somebody polled. That turned a flood into a permanent
            // refusal whose only cure was a restart, and a restart drops the
            // genuine undelivered mail with it. Reach those inboxes before
            // refusing anybody. Rate limited: see FULL_STORE_SWEEP_INTERVAL.
            let dropped = inboxes.sweep_expired();
            if dropped > 0 {
                tracing::info!(
                    dropped,
                    "swept expired messenger mail from a full relay store"
                );
            }
        }
        if inboxes.envelopes >= MAX_TOTAL_ENVELOPES || inboxes.bytes + size > MAX_TOTAL_BYTES {
            return Err("this relay is full".into());
        }

        inboxes.insert(to, envelope);
        Ok(())
    }

    /// Write down the key an accepted envelope was sent with.
    ///
    /// The binding is re-checked here rather than assumed from the caller. It
    /// costs one hash per accepted send and it means the table cannot hold an
    /// entry whose key does not derive to its own address even if some future
    /// caller forgets to authenticate first. That is defence in depth and not
    /// the guarantee: the guarantee is that the asking wallet checks it again.
    async fn remember_sender_key(&self, envelope: &MessengerEnvelope) {
        let from = envelope.from.trim();
        let Some(pubkey_hex) = envelope.from_pubkey.as_deref().map(str::trim) else {
            return;
        };
        let Ok(bytes) = hex::decode(pubkey_hex) else {
            return;
        };
        let Ok(pubkey): Result<[u8; 33], _> = bytes.try_into() else {
            return;
        };
        if !crate::messenger_auth::pubkey_matches_address(&pubkey, from) {
            return;
        }
        let now = Instant::now();
        let mut dir = self.directory.lock().await;
        // A full table drops its stalest entries rather than refusing to learn.
        // Either way the worst case is "no key", which is the honest fallback.
        //
        // Expiry and eviction both happen here, on the write path, and both are
        // done in batches. The write path is the expensive place to be: it costs
        // the caller a signed envelope this relay has already verified and
        // accepted, and a batch of `DIRECTORY_EVICT_BATCH` means the sort is
        // paid once per that many inserts rather than a full scan per insert.
        // The read path does neither, so an unauthenticated question is never
        // the thing that walks the table. See `sender_key`.
        if dir.len() >= MAX_DIRECTORY_ENTRIES {
            dir.retain(|_, entry| now.duration_since(entry.seen) < DIRECTORY_TTL);
        }
        if dir.len() >= MAX_DIRECTORY_ENTRIES && !dir.contains_key(from) {
            let mut by_age: Vec<(String, Instant)> =
                dir.iter().map(|(k, e)| (k.clone(), e.seen)).collect();
            by_age.sort_by_key(|(_, seen)| *seen);
            let want = dir.len() + 1 - MAX_DIRECTORY_ENTRIES;
            for (stale, _) in by_age.into_iter().take(want.max(DIRECTORY_EVICT_BATCH)) {
                dir.remove(&stale);
            }
        }
        dir.insert(
            from.to_string(),
            DirectoryEntry {
                pubkey: hex::encode(pubkey),
                seen: now,
            },
        );
    }

    /// The last key seen for this address, or nothing.
    ///
    /// One lookup and one age comparison, and deliberately no sweep: this is
    /// the only unauthenticated question the directory answers, and a sweep
    /// here would let anyone who can reach the port make the relay walk the
    /// whole table, under the same lock an accepted send needs, for the price
    /// of a request. Expiry is enforced by refusing to answer with an entry
    /// past its TTL, which is indistinguishable from the entry being gone;
    /// the storage it occupies is reclaimed on the write path, which costs the
    /// caller a signed envelope. See `remember_sender_key`.
    async fn sender_key(&self, address: &str) -> Option<String> {
        // The relay answers this question only about the people it is for.
        // Unlisted, the answer is `None`, which is byte-identical to the answer
        // for an address this relay has genuinely never seen and to the answer
        // for one whose entry has expired: the directory cannot be used to ask
        // who is on somebody's list. Opened deliberately to everybody, it
        // answers about anybody, which is the correspondent-confirmation oracle
        // section 6.2 describes and is now something an operator has to ask for
        // by name.
        if !self.allows(address) {
            return None;
        }
        let now = Instant::now();
        let dir = self.directory.lock().await;
        let entry = dir.get(address)?;
        if now.duration_since(entry.seen) >= DIRECTORY_TTL {
            return None;
        }
        Some(entry.pubkey.clone())
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
    /// Who may push a transaction through this relay to the operator's node.
    /// A separate decision from the mail allowlist, and separately denied by
    /// default. See `crate::relay::SubmitAccess`.
    pub submit: crate::relay::SubmitAccess,
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
        .route(MESSENGER_PUBKEY_PATH, post(pubkey_handler))
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
    // Cloned before the move so the directory records the key of an envelope
    // this relay actually accepted, and only then.
    let accepted = req.envelope.clone();
    match state.inbox.push(req.envelope).await {
        Ok(()) => {
            state.inbox.remember_sender_key(&accepted).await;
            Json(MessengerSendResponse {
                ok: true,
                err: None,
            })
        }
        Err(e) => Json(MessengerSendResponse {
            ok: false,
            err: Some(e),
        }),
    }
}

/// The last public key this relay saw the named address send with.
///
/// # Why the ASKER has to prove who they are
///
/// This route used to be unauthenticated, on the reasoning that the wallet
/// which needs it is by definition a stranger to the address it is asking
/// about. That reasoning was wrong in the one way that matters. The answer
/// differed by whether the address was on the operator's list: a listed
/// address that had sent recently came back with a key, and everything else
/// came back with `None`. So anybody who could open the socket could put
/// candidate addresses to it and read the host's list back out - the single
/// fact the whole design says only the host holds, which is that these two
/// people talk to each other, handed to a passer-by.
///
/// A refusal cannot be made symmetric here by inventing an answer, because a
/// Hacash address IS the hash of its own public key: a decoy key does not
/// derive to the address asked about, so the asker can tell a decoy from a
/// real answer with a hash. The only way to close it is to stop answering
/// strangers, so the asker now presents the same credential the inbox route
/// wants - their own address, a nonce this relay issued for it, and a
/// signature - and the relay answers only somebody it already carries mail
/// for. An unauthenticated caller gets `None` for every address in the world,
/// which is one answer and therefore no oracle.
///
/// The key itself was never the secret: it is on the chain the moment that
/// account signs anything, and it rides in clear on every envelope this relay
/// forwards. What is now protected is the association between an address and
/// this relay. Section 6.2 of docs/RUNNING-A-RELAY.md states what is left for
/// the operator to weigh.
///
/// It is deliberately not made cheaper to abuse than it has to be: an address
/// no key could ever sign for is refused without touching the table, the answer
/// for an unknown address is byte-identical to the answer for an address whose
/// entry has expired, and answering costs one hash lookup rather than a walk of
/// the table (`sender_key`).
///
/// It is a POST, not a GET, so the address being asked about does not end up in
/// this relay's access log or in the log of any proxy in front of it. That is
/// the operator's own metadata hygiene, not the wallet's: see section 6.4.
async fn pubkey_handler(
    State(state): State<RelayAppState>,
    Json(req): Json<MessengerPubkeyRequest>,
) -> Json<MessengerPubkeyResponse> {
    let nothing = || Json(MessengerPubkeyResponse { pubkey: None });
    let address = req.address.trim();
    if address.is_empty() || !is_claimable_address(address) {
        return nothing();
    }
    // Who is asking, checked before anything about the address asked about is
    // looked at, and answered with the identical `None` on every failure.
    let asker = req.asker.trim();
    if asker.is_empty()
        || !crate::messenger_auth::verify_inbox_auth(
            asker,
            req.nonce.trim(),
            &req.asker_pubkey,
            &req.signature,
        )
    {
        return nothing();
    }
    // Short-circuits before the challenge table is touched, so an unlisted
    // asker cannot spend a nonce and cannot make the relay do work either.
    if !state.inbox.allows(asker) || !state.inbox.consume_challenge(asker, req.nonce.trim()).await {
        return nothing();
    }
    Json(MessengerPubkeyResponse {
        pubkey: state.inbox.sender_key(address).await,
    })
}

/// A nonce, and the same shape of nonce for everybody.
///
/// # Why a refused caller is handed one too
///
/// This used to answer an unlisted address with an EMPTY nonce and a listed one
/// with sixteen bytes of hex. That is a membership test anybody who can open
/// the socket may run, once per candidate address, with no key and no
/// relationship with the host: listed answers long, unlisted answers short. A
/// neighbour on the same network could reconstruct a host's whole correspondent
/// list from a handful of guesses. The refusal was symmetric - an address the
/// operator left off looked exactly like one the relay had never heard of - but
/// the ACCEPTANCE was not, and it is the acceptance that carries the fact.
///
/// So every caller gets a well formed nonce now, and only a caller this relay
/// carries mail for gets one that is written down. A decoy is sixteen fresh
/// random bytes that no table has ever seen, so `consume_challenge` refuses it
/// exactly as it refuses an expired one, and `inbox_handler` and `ack_handler`
/// refuse the address before the nonce is even reached. Nothing is stored for a
/// decoy, so this cannot be used to fill the challenge table either - which is
/// also why an address no key could ever sign for is handed a decoy rather than
/// a real challenge.
///
/// What a caller can still learn from this route: nothing. Listed, unlisted,
/// unclaimable and never-heard-of all receive one 32 character hex nonce and an
/// expiry `CHALLENGE_TTL` from now.
async fn challenge_handler(
    State(state): State<RelayAppState>,
    Query(q): Query<ChallengeQuery>,
) -> Json<MessengerChallengeResponse> {
    let to = q.to.trim();
    if to.is_empty() || !is_claimable_address(to) || !state.inbox.allows(to) {
        return Json(decoy_challenge());
    }
    Json(state.inbox.issue_challenge(to).await)
}

/// A nonce that is never written down, indistinguishable from one that is.
fn decoy_challenge() -> MessengerChallengeResponse {
    let mut nonce_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    MessengerChallengeResponse {
        nonce: hex::encode(nonce_bytes),
        expires_at: (Utc::now() + ChronoDuration::seconds(CHALLENGE_TTL.as_secs() as i64))
            .to_rfc3339(),
    }
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
    // Signature first, then the list, then the nonce. Every failure answers
    // with the identical `refused()` - no messages and `auth_ok: false` - so
    // this route has never been able to say whether an address is on somebody's
    // list. The ORDER is what changed: the list used to be checked first, which
    // made an unlisted address answer without a signature verification while a
    // listed one paid for one, and identical bytes that arrive at measurably
    // different times are still an answer. Doing the same work for both leaves
    // nothing to compare.
    //
    // Checking the signature before spending the nonce is the older reason for
    // this order and still holds: consuming it first meant any caller could
    // burn the challenge the owner was about to use, and the owner's own
    // correctly signed fetch then came back empty.
    if !crate::messenger_auth::verify_inbox_auth(
        to,
        req.nonce.trim(),
        &req.claimant_pubkey,
        &req.signature,
    ) {
        return refused();
    }
    // Default deny, short-circuiting before the challenge table is touched. An
    // unlisted address is also unreachable here in practice, because
    // `challenge_handler` only ever hands it a decoy - which is exactly why it
    // is checked here too. A door that is only shut upstream is a door.
    if !state.inbox.allows(to) || !state.inbox.consume_challenge(to, req.nonce.trim()).await {
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
    // SIGNATURE FIRST, AND THE LIST FOLDED INTO THE CHALLENGE CHECK.
    //
    // The list used to be checked first and answered "invalid or expired
    // challenge" while a listed caller with a bad signature was answered
    // "invalid inbox auth signature". Two different sentences, chosen by list
    // membership, from identical garbage credentials: that is the same
    // membership oracle the challenge route carried, in words. Checking the
    // signature first makes the two answers depend on what the caller sent and
    // not on who the operator listed - an unlisted address that signs properly
    // gets "invalid or expired challenge", which is what a listed address with
    // a stale nonce gets, and any address that signs badly gets the signature
    // sentence.
    //
    // It also keeps the property the order was originally for: a caller who
    // cannot sign for this address never reaches `consume_challenge`, so it
    // cannot burn the challenge the owner was about to spend.
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
    // Default deny, short-circuiting before the challenge table is touched. An
    // unlisted caller can hold no challenge for this address anyway, because
    // `challenge_handler` only ever hands them a decoy, so this sentence is the
    // literal truth as well as being the one a listed caller with a spent nonce
    // receives.
    if !state.inbox.allows(to) || !state.inbox.consume_challenge(to, req.nonce.trim()).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(to: &str, id: &str) -> MessengerEnvelope {
        MessengerEnvelope {
            v: 1,
            id: id.to_string(),
            to: to.to_string(),
            from: "1SomeSender".to_string(),
            from_pubkey: None,
            from_sig: None,
            nonce: "00".to_string(),
            ciphertext: "deadbeef".to_string(),
            sent_at: Utc::now().to_rfc3339(),
        }
    }

    /// THE BUG THIS SWEEP EXISTS FOR.
    ///
    /// `prune` only ever ran on an inbox somebody touched, and a flood is
    /// posted to inboxes its author never comes back to. So expired envelopes
    /// in those inboxes kept counting against the whole store's ceilings for
    /// ever rather than for `TTL`: the relay stayed full permanently, and the
    /// only cure was restarting the wallet, which throws away every genuine
    /// undelivered message with it.
    #[test]
    fn expiry_reaches_an_inbox_nobody_ever_comes_back_to() {
        let mut inboxes = Inboxes::default();
        inboxes.insert("1Untouched".into(), envelope("1Untouched", "flood-1"));
        inboxes.insert("1Untouched".into(), envelope("1Untouched", "flood-2"));
        inboxes.insert("1Friend".into(), envelope("1Friend", "genuine-1"));
        assert_eq!(inboxes.envelopes, 3);
        let bytes_before = inboxes.bytes;
        assert!(bytes_before > 0);

        // A week goes by for the flood, and one more envelope arrives for the
        // friend on the far side of it. Nobody polls the flooded mailboxes, so
        // nothing has ever called `prune` on them.
        let a_week_later = Instant::now() + TTL + Duration::from_secs(60);
        inboxes.map.get_mut("1Friend").expect("inbox")[0].received = a_week_later;

        inboxes.prune("1Friend");
        assert_eq!(
            inboxes.envelopes, 3,
            "pruning the inbox somebody DID touch is what used to be the whole of expiry"
        );

        assert_eq!(inboxes.sweep_expired_at(a_week_later), 2);
        assert_eq!(inboxes.envelopes, 1, "the slots were never given back");
        assert!(inboxes.bytes < bytes_before);
        assert!(!inboxes.map.contains_key("1Untouched"));
        assert_eq!(
            inboxes.list("1Friend").len(),
            1,
            "the sweep took mail that had not expired"
        );
    }

    /// A sweep is O(inboxes) and the caller is a refused send, so it must not
    /// be something an outsider can make the relay do once per request.
    #[test]
    fn a_full_store_does_not_walk_itself_once_per_refused_send() {
        let mut inboxes = Inboxes::default();
        assert!(
            inboxes.may_sweep(),
            "a store that has never swept has to be allowed to"
        );
        let now = Instant::now();
        inboxes.sweep_expired_at(now);
        assert!(
            !inboxes.may_sweep_at(now),
            "the second refusal in the same instant swept again"
        );
        assert!(
            !inboxes.may_sweep_at(now + FULL_STORE_SWEEP_INTERVAL - Duration::from_secs(1)),
            "the interval is not being waited out"
        );
        assert!(
            inboxes.may_sweep_at(now + FULL_STORE_SWEEP_INTERVAL),
            "the interval never elapses"
        );
    }

    /// An empty list is nobody, and every way of arriving at one is nobody.
    ///
    /// This is the default, and it is the state an upgraded settings file is in
    /// (`#[serde(default)]` on `relay_allowlist`), so it is the state a person
    /// who never made a choice is in. It has to be the state that exposes them
    /// to nothing.
    #[test]
    fn an_unnamed_relay_carries_mail_for_nobody() {
        for list in [
            InboxAllowlist::closed(),
            InboxAllowlist::default(),
            InboxAllowlist::from_addresses(Vec::<String>::new()),
            // Whitespace is not a name.
            InboxAllowlist::from_addresses(["", "  ", "	"]),
        ] {
            assert!(list.serves_nobody());
            assert!(!list.serves_everybody());
            assert!(list.is_empty());
            assert_eq!(list.len(), 0);
            assert!(!list.allows("1Anybody"));
            assert!(!list.allows(""));
        }
    }

    /// The one open relay, and the only way to get one.
    #[test]
    fn serving_everybody_is_reachable_only_by_asking_for_it_by_name() {
        let list = InboxAllowlist::serving_everybody();
        assert!(list.serves_everybody());
        assert!(!list.serves_nobody());
        assert!(list.allows("1Anybody"));
        // And it is not what any default gives you.
        assert!(!InboxAllowlist::default().serves_everybody());
        assert!(!MessengerInbox::new().allowlist().serves_everybody());
        assert!(MessengerInbox::new().allowlist().serves_nobody());
    }

    /// Named, it is exact. A typo is an address that never matches, which costs
    /// the person who made it their own mail and can never open the relay to
    /// everybody.
    #[test]
    fn a_named_relay_matches_the_address_and_nothing_near_it() {
        let list = InboxAllowlist::from_addresses(["  1Alice ", "1Bob"]);
        assert!(!list.serves_nobody());
        assert!(!list.serves_everybody());
        assert_eq!(list.len(), 2);
        assert!(list.allows("1Alice"));
        assert!(list.allows(" 1Alice"));
        assert!(list.allows("1Bob"));
        assert!(!list.allows("1Alic"));
        assert!(!list.allows("1AliceX"));
        assert!(!list.allows("1alice"));
        assert!(!list.allows("1Mallory"));
        assert!(!list.allows(""));
    }
}
