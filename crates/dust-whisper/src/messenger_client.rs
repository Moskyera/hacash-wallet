use std::time::Duration;

use reqwest::Client;

use crate::error::{WhisperError, WhisperResult};
use crate::http_util::{ensure_success, json_capped};
use crate::protocol::{
    MESSENGER_ACK_PATH, MESSENGER_CHALLENGE_PATH, MESSENGER_INBOX_PATH, MESSENGER_PUBKEY_PATH,
    MESSENGER_SEND_PATH, MessengerAckRequest, MessengerAckResponse, MessengerChallengeResponse,
    MessengerEnvelope, MessengerInboxRequest, MessengerInboxResponse, MessengerPubkeyRequest,
    MessengerPubkeyResponse, MessengerSendRequest, MessengerSendResponse,
};

fn base_url(relay_url: &str) -> String {
    relay_url.trim().trim_end_matches('/').to_string()
}

pub async fn send_envelope(
    http: &Client,
    relay_url: &str,
    envelope: MessengerEnvelope,
) -> WhisperResult<()> {
    let url = format!("{}{}", base_url(relay_url), MESSENGER_SEND_PATH);
    let resp = http
        .post(url)
        .json(&MessengerSendRequest { envelope })
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger send: {e}")))?;
    let resp = ensure_success(resp, "messenger send").await?;
    let body: MessengerSendResponse = resp
        .json()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger send json: {e}")))?;
    if !body.ok {
        return Err(WhisperError::Relay(
            body.err.unwrap_or_else(|| "messenger send failed".into()),
        ));
    }
    Ok(())
}

pub async fn fetch_challenge(
    http: &Client,
    relay_url: &str,
    to_address: &str,
) -> WhisperResult<MessengerChallengeResponse> {
    let url = format!(
        "{}{MESSENGER_CHALLENGE_PATH}?to={}",
        base_url(relay_url),
        urlencoding::encode(to_address)
    );
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger challenge: {e}")))?;
    let resp = ensure_success(resp, "messenger challenge").await?;
    resp.json()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger challenge json: {e}")))
}

/// The most this will read of a directory answer.
///
/// A real answer is a 66 character hex key inside a small JSON object. Anything
/// past a kilobyte is not an answer, and reading it would only spend this
/// wallet's memory on a peer's say-so.
pub const MAX_PUBKEY_RESPONSE_BYTES: usize = 1024;

/// Who is asking the key directory, and their proof of it.
///
/// One nonce per relay, because a nonce is issued by one relay and spent at
/// that same relay. The caller obtains it from `fetch_challenge` against the
/// relay it is about to ask.
pub struct PubkeyAsker<'a> {
    /// The asking wallet's own Hacash address.
    pub address: &'a str,
    /// Its compressed secp256k1 public key, hex.
    pub pubkey_hex: &'a str,
    /// A nonce this relay issued for `address`.
    pub nonce: &'a str,
    /// `inbox_auth_digest(address, nonce)` signed by that key, hex.
    pub signature: &'a str,
}

/// Ask a relay for the last public key it saw an address send with.
///
/// The answer is a claim by the relay and this function does nothing to check
/// it. It is a string of hex, or nothing. The caller
/// (`wallet-core/src/messenger.rs::lookup_peer_key`) re-derives the address
/// from it and discards it unless it matches the address that was asked about,
/// which is the only reason it is safe to ask a relay this question at all.
///
/// # Why the caller has to name a deadline
///
/// This runs on the send path, before the message moves, and it is asked of
/// relays this wallet has no relationship with yet. On the shared client's
/// 20 second budget three unreachable relays put a minute on the clock of a
/// person pressing Send, every time, because a lookup that finds nothing
/// learns nothing and so is repeated on the next message too. The caller owns
/// the whole lookup's budget and passes what is left of it here, so a stalling
/// relay costs a short wait and then the honest v1 fallback.
///
/// The address is posted in a body rather than hung off a query string, so it
/// does not land in the access log of every relay asked. See
/// `MessengerPubkeyRequest`.
///
/// # Why this now carries a credential
///
/// The relay answers this only for somebody it already carries mail for, so the
/// caller has to say who it is and prove it. `asker` is this wallet's own
/// address, `nonce` is one the same relay issued for that address, and
/// `signature` is `inbox_auth_digest(asker, nonce)` signed by its key - the
/// identical credential the inbox route wants, because it is the identical
/// question: is this caller one of the people this relay is for. A relay this
/// wallet is not listed on answers `None`, which is what it answered before and
/// lands on the same honest v1 fallback.
pub async fn fetch_peer_pubkey(
    http: &Client,
    relay_url: &str,
    address: &str,
    asker: &PubkeyAsker<'_>,
    timeout: Duration,
) -> WhisperResult<Option<String>> {
    let url = format!("{}{MESSENGER_PUBKEY_PATH}", base_url(relay_url));
    let resp = http
        .post(url)
        .timeout(timeout)
        .json(&MessengerPubkeyRequest {
            address: address.to_string(),
            asker: asker.address.to_string(),
            asker_pubkey: asker.pubkey_hex.to_string(),
            nonce: asker.nonce.to_string(),
            signature: asker.signature.to_string(),
        })
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger pubkey: {e}")))?;
    let resp = ensure_success(resp, "messenger pubkey").await?;
    let body: MessengerPubkeyResponse =
        json_capped(resp, MAX_PUBKEY_RESPONSE_BYTES, "messenger pubkey").await?;
    Ok(body.pubkey)
}

/// Fetch an inbox and report the whole answer, not just its contents.
///
/// The caller needs `auth_ok` as much as it needs the messages: a refused claim
/// and an empty inbox both come back with zero envelopes, and a screen that
/// cannot tell them apart tells somebody who has been locked out that they have
/// no mail.
pub async fn fetch_inbox(
    http: &Client,
    relay_url: &str,
    request: &MessengerInboxRequest,
) -> WhisperResult<MessengerInboxResponse> {
    let url = format!("{}{}", base_url(relay_url), MESSENGER_INBOX_PATH);
    let resp = http
        .post(url)
        .json(request)
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger inbox: {e}")))?;
    let resp = ensure_success(resp, "messenger inbox").await?;
    resp.json()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger inbox json: {e}")))
}

pub async fn ack_messages(
    http: &Client,
    relay_url: &str,
    request: &MessengerAckRequest,
) -> WhisperResult<u32> {
    let url = format!("{}{}", base_url(relay_url), MESSENGER_ACK_PATH);
    let resp = http
        .post(url)
        .json(request)
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger ack: {e}")))?;
    let resp = ensure_success(resp, "messenger ack").await?;
    let body: MessengerAckResponse = resp
        .json()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger ack json: {e}")))?;
    if !body.ok {
        return Err(WhisperError::Relay(
            body.err.unwrap_or_else(|| "messenger ack failed".into()),
        ));
    }
    Ok(body.removed)
}
