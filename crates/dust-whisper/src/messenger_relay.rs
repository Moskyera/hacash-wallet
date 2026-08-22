//! In-memory messenger inbox on the DUST Whisper relay.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
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
const MAX_PER_SENDER: usize = 20;
const TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// Ceiling on outstanding challenges across the whole relay.
///
/// Challenges are keyed by their own nonce rather than by address. Keyed by
/// address there was exactly one slot per person and anybody could overwrite
/// it, which silently locked the owner out of their own inbox for as long as
/// the attacker kept asking. Keyed by nonce there is nothing to aim at.
const MAX_PENDING_CHALLENGES: usize = 8192;

#[derive(Clone)]
struct Stored {
    envelope: MessengerEnvelope,
    received: Instant,
}

#[derive(Clone)]
struct Challenge {
    to: String,
    expires: Instant,
}

#[derive(Clone, Default)]
pub struct MessengerInbox {
    inner: Arc<Mutex<HashMap<String, Vec<Stored>>>>,
    /// Nonce -> the address it was issued for. Never keyed by address.
    challenges: Arc<Mutex<HashMap<String, Challenge>>>,
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
        let from = envelope.from.trim().to_string();
        let mut map = self.inner.lock().await;
        let list = map.entry(to).or_default();
        list.retain(|s| s.received.elapsed() < TTL);
        let from_this_sender = list
            .iter()
            .filter(|s| s.envelope.from.trim() == from)
            .count();
        if from_this_sender >= MAX_PER_SENDER {
            // This sender is already using its whole share. Drop its own oldest
            // entry rather than somebody else's.
            if let Some(idx) = list.iter().position(|s| s.envelope.from.trim() == from) {
                list.remove(idx);
            }
        } else if list.len() >= MAX_PER_RECIPIENT {
            // The inbox is full of other people's mail. Evict from whichever
            // sender is taking up the most room, oldest of theirs first, so a
            // flood costs the flooder and not the person being written to.
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for s in list.iter() {
                *counts.entry(s.envelope.from.trim()).or_default() += 1;
            }
            let Some((&worst, _)) = counts.iter().max_by_key(|&(_, &n)| n) else {
                return Err("inbox full".into());
            };
            let worst = worst.to_string();
            if let Some(idx) = list.iter().position(|s| s.envelope.from.trim() == worst) {
                list.remove(idx);
            }
        }
        list.push(Stored {
            envelope,
            received: Instant::now(),
        });
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
        if map.len() >= MAX_PENDING_CHALLENGES {
            // Refuse to issue rather than evict somebody else's live challenge.
            // An empty nonce never verifies, so the caller is told no by the
            // same path a wrong nonce takes.
            return MessengerChallengeResponse {
                nonce: String::new(),
                expires_at,
            };
        }
        map.insert(
            nonce.clone(),
            Challenge {
                to: to.to_string(),
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
        let mut map = self.inner.lock().await;
        let Some(list) = map.get_mut(to) else {
            return Vec::new();
        };
        list.retain(|s| s.received.elapsed() < TTL);
        list.iter().map(|s| s.envelope.clone()).collect()
    }

    async fn ack(&self, to: &str, ids: &[String]) -> u32 {
        let mut map = self.inner.lock().await;
        let Some(list) = map.get_mut(to) else {
            return 0;
        };
        list.retain(|s| s.received.elapsed() < TTL);
        let before = list.len();
        if ids.is_empty() {
            list.clear();
        } else {
            list.retain(|s| !ids.contains(&s.envelope.id));
        }
        let removed = before.saturating_sub(list.len()) as u32;
        if list.is_empty() {
            map.remove(to);
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
    if to.is_empty() {
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
