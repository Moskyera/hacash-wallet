use reqwest::Response;

use crate::error::{WhisperError, WhisperResult};

pub async fn ensure_success(resp: Response, context: &str) -> WhisperResult<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    let snippet: String = body.chars().take(240).collect();
    Err(WhisperError::Relay(format!(
        "{context}: HTTP {status}{}",
        if snippet.is_empty() {
            String::new()
        } else {
            format!(". {snippet}")
        }
    )))
}
