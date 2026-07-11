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
    MessengerAckRequest, MessengerAckResponse, MessengerChallengeResponse, MessengerEnvelope,
    MessengerInboxRequest, MessengerInboxResponse, MessengerSendRequest, MessengerSendResponse,
    MESSENGER_ACK_PATH, MESSENGER_CHALLENGE_PATH, MESSENGER_INBOX_PATH, MESSENGER_SEND_PATH,
};

const MAX_PER_RECIPIENT: usize = 200;
const TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const CHALLENGE_TTL: Duration = Duration::from_secs(120);

#[derive(Clone)]
struct Stored {
    envelope: MessengerEnvelope,
    received: Instant,
}

#[derive(Clone)]
struct Challenge {
    nonce: String,
    expires: Instant,
}

#[derive(Clone, Default)]
pub struct MessengerInbox {
    inner: Arc<Mutex<HashMap<String, Vec<Stored>>>>,
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
        let mut map = self.inner.lock().await;
        let list = map.entry(to).or_default();
        list.retain(|s| s.received.elapsed() < TTL);
        if list.len() >= MAX_PER_RECIPIENT {
            list.remove(0);
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
        let expires_at = (Utc::now() + ChronoDuration::seconds(CHALLENGE_TTL.as_secs() as i64))
            .to_rfc3339();
        let mut map = self.challenges.lock().await;
        map.insert(
            to.to_string(),
            Challenge {
                nonce: nonce.clone(),
                expires: Instant::now() + CHALLENGE_TTL,
            },
        );
        MessengerChallengeResponse { nonce, expires_at }
    }

    async fn consume_challenge(&self, to: &str, nonce: &str) -> bool {
        let mut map = self.challenges.lock().await;
        let Some(ch) = map.get(to) else {
            return false;
        };
        if ch.expires < Instant::now() || ch.nonce != nonce {
            return false;
        }
        map.remove(to);
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
    if to.is_empty() {
        return Json(MessengerInboxResponse { messages: Vec::new() });
    }
    if !state.inbox.consume_challenge(to, req.nonce.trim()).await {
        return Json(MessengerInboxResponse { messages: Vec::new() });
    }
    if !crate::messenger_auth::verify_inbox_auth(
        to,
        req.nonce.trim(),
        &req.claimant_pubkey,
        &req.signature,
    ) {
        return Json(MessengerInboxResponse { messages: Vec::new() });
    }
    let messages = state.inbox.peek(to).await;
    Json(MessengerInboxResponse { messages })
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
    if !state.inbox.consume_challenge(to, req.nonce.trim()).await {
        return Json(MessengerAckResponse {
            ok: false,
            removed: 0,
            err: Some("invalid or expired challenge".into()),
        });
    }
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
    let removed = state.inbox.ack(to, &req.ids).await;
    Json(MessengerAckResponse {
        ok: true,
        removed,
        err: None,
    })
}