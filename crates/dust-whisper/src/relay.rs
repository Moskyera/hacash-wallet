use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use reqwest::Client;
use serde_json::json;
use tower_http::trace::TraceLayer;

use crate::crypto::{decrypt_payload, public_key_from_secret};
use crate::error::WhisperError;
use crate::http_util::ensure_success;
use crate::protocol::{
    WhisperInfo, WhisperSubmitRequest, WhisperSubmitResponse, INFO_PATH, PROTOCOL_VERSION,
    SUBMIT_PATH,
};

/// Max encrypted envelope size accepted by the relay (generous for large type-4 txs).
pub const MAX_SUBMIT_BODY_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct RelayState {
    pub secret_key: [u8; 32],
    pub public_key_b64: String,
    pub default_node_url: String,
    pub http: Client,
}

pub fn build_router(state: RelayState) -> Router {
    Router::new()
        .route(INFO_PATH, get(info_handler))
        .route(SUBMIT_PATH, post(submit_handler))
        .layer(DefaultBodyLimit::max(MAX_SUBMIT_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(state))
}

pub async fn serve(addr: SocketAddr, state: RelayState) -> std::io::Result<()> {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "DUST Whisper relay listening");
    axum::serve(listener, app).await
}

async fn info_handler(State(state): State<Arc<RelayState>>) -> Json<WhisperInfo> {
    Json(WhisperInfo {
        v: PROTOCOL_VERSION,
        pubkey: state.public_key_b64.clone(),
        // Informational only — relay always forwards to its configured node URL.
        node_url: Some(state.default_node_url.clone()),
    })
}

async fn submit_handler(
    State(state): State<Arc<RelayState>>,
    Json(request): Json<WhisperSubmitRequest>,
) -> Json<WhisperSubmitResponse> {
    match forward_submit(&state, &request).await {
        Ok(resp) => Json(resp),
        Err(e) => {
            tracing::warn!(error = %e, "whisper submit failed");
            Json(WhisperSubmitResponse {
                ret: 1,
                err: Some(e.to_string()),
                message: None,
                hash: None,
            })
        }
    }
}

async fn forward_submit(
    state: &RelayState,
    request: &WhisperSubmitRequest,
) -> Result<WhisperSubmitResponse, WhisperError> {
    let inner = decrypt_payload(&state.secret_key, request)?;

    if inner.tx_hex.is_empty() {
        return Err(WhisperError::Protocol("empty tx_hex".into()));
    }
    if inner.tx_hex.len() > MAX_SUBMIT_BODY_BYTES {
        return Err(WhisperError::Protocol("tx_hex too large".into()));
    }

    // Always use operator-configured node URL — never trust client-supplied targets (SSRF).
    let node_url = state.default_node_url.trim().trim_end_matches('/');
    if node_url.is_empty() {
        return Err(WhisperError::Relay("relay node_url not configured".into()));
    }

    let url = format!("{node_url}/submit/transaction?hexbody=true");
    let resp = state
        .http
        .post(url)
        .body(inner.tx_hex.clone())
        .header("content-type", "text/plain")
        .send()
        .await
        .map_err(|e| WhisperError::Relay(format!("node forward: {e}")))?;

    let resp = ensure_success(resp, "node submit").await?;
    let body: WhisperSubmitResponse = resp
        .json()
        .await
        .map_err(|e| WhisperError::Relay(format!("node response JSON: {e}")))?;

    if body.ret != 0 {
        return Err(WhisperError::Relay(
            body.err
                .clone()
                .or(body.message.clone())
                .unwrap_or_else(|| format!("node submit ret={}", body.ret)),
        ));
    }

    Ok(body)
}

pub fn relay_state_from_secret(secret: [u8; 32], default_node_url: String) -> RelayState {
    let pk = public_key_from_secret(&secret);
    let public_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        pk,
    );
    RelayState {
        secret_key: secret,
        public_key_b64,
        default_node_url,
        http: Client::new(),
    }
}

pub fn parse_secret_hex(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("invalid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "secret key must be 32 bytes (64 hex chars)".into())
}

pub fn relay_info_json(state: &RelayState) -> serde_json::Value {
    json!({
        "v": PROTOCOL_VERSION,
        "pubkey": state.public_key_b64,
        "node_url": state.default_node_url,
    })
}