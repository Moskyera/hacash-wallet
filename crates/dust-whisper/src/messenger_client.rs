use reqwest::Client;

use crate::error::{WhisperError, WhisperResult};
use crate::http_util::ensure_success;
use crate::protocol::{
    MessengerAckRequest, MessengerAckResponse, MessengerChallengeResponse, MessengerEnvelope,
    MessengerInboxRequest, MessengerInboxResponse, MessengerSendRequest, MessengerSendResponse,
    MESSENGER_ACK_PATH, MESSENGER_CHALLENGE_PATH, MESSENGER_INBOX_PATH, MESSENGER_SEND_PATH,
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

pub async fn fetch_inbox(
    http: &Client,
    relay_url: &str,
    request: &MessengerInboxRequest,
) -> WhisperResult<Vec<MessengerEnvelope>> {
    let url = format!("{}{}", base_url(relay_url), MESSENGER_INBOX_PATH);
    let resp = http
        .post(url)
        .json(request)
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger inbox: {e}")))?;
    let resp = ensure_success(resp, "messenger inbox").await?;
    let body: MessengerInboxResponse = resp
        .json()
        .await
        .map_err(|e| WhisperError::Relay(format!("messenger inbox json: {e}")))?;
    Ok(body.messages)
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