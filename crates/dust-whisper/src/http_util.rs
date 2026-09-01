use reqwest::Response;
use serde::de::DeserializeOwned;

use crate::error::{WhisperError, WhisperResult};

/// How much of a failed response this will read before giving up on the
/// explanation.
///
/// The snippet that reaches a person is 240 characters. Reading a gigabyte to
/// print 240 characters of it is a free way for whatever answered to spend this
/// process's memory, and the failure path is the one an unhealthy or hostile
/// peer controls completely.
const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

/// Read at most `cap` bytes of a response body, refusing rather than truncating.
///
/// `Response::bytes` and `Response::json` buffer whatever arrives, however much
/// that is, and neither the length header nor the sender's good intentions bound
/// it. This reads chunk by chunk and stops the moment the total would pass the
/// cap, so a peer that answers with something enormous costs one connection and
/// `cap` bytes rather than however much it felt like sending.
///
/// A `Content-Length` over the cap is refused before a single chunk is read; it
/// is a hint, not a guarantee, which is why the running total is checked too.
async fn read_capped(resp: Response, cap: usize, context: &str) -> WhisperResult<Vec<u8>> {
    if let Some(len) = resp.content_length()
        && len > cap as u64
    {
        return Err(WhisperError::Relay(format!(
            "{context}: answer is {len} bytes, which is more than this wallet will read ({cap})"
        )));
    }
    let mut resp = resp;
    let mut out: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| WhisperError::Relay(format!("{context}: {e}")))?
    {
        if out.len().saturating_add(chunk.len()) > cap {
            return Err(WhisperError::Relay(format!(
                "{context}: answer is longer than this wallet will read ({cap} bytes)"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Parse a JSON answer that is known to be small, and refuse one that is not.
pub async fn json_capped<T: DeserializeOwned>(
    resp: Response,
    cap: usize,
    context: &str,
) -> WhisperResult<T> {
    let body = read_capped(resp, cap, context).await?;
    serde_json::from_slice(&body).map_err(|e| WhisperError::Relay(format!("{context} json: {e}")))
}

pub async fn ensure_success(resp: Response, context: &str) -> WhisperResult<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = read_capped(resp, MAX_ERROR_BODY_BYTES, context)
        .await
        .unwrap_or_default();
    let snippet: String = String::from_utf8_lossy(&body).chars().take(240).collect();
    Err(WhisperError::Relay(format!(
        "{context}: HTTP {status}{}",
        if snippet.is_empty() {
            String::new()
        } else {
            format!(". {snippet}")
        }
    )))
}
