use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, extract::DefaultBodyLimit};
use tower_http::trace::TraceLayer;

use crate::api::{
    ConfirmFastPayRequest, FastPayInboxItem, FastPayRequest, FastPayResponse, HubHealth,
};
use crate::error::HubError;
use crate::state::HubState;

pub const MAX_HUB_REQUEST_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<HubState>,
}

pub fn build_router(hub: Arc<HubState>) -> Router {
    Router::new()
        .route("/v1/health", get(health_handler))
        .route("/v1/readiness/mainnet", get(mainnet_readiness_handler))
        .route("/v1/fast-pay", post(fast_pay_handler))
        .route("/v1/fast-pay/inbox/{payee}", get(recipient_inbox_handler))
        .route("/v1/fast-pay/{payment_id}", get(payment_status_handler))
        .route(
            "/v1/fast-pay/{payment_id}/confirm",
            post(confirm_fast_pay_handler),
        )
        .layer(DefaultBodyLimit::max(MAX_HUB_REQUEST_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState { hub })
}

async fn confirm_fast_pay_handler(
    State(state): State<AppState>,
    Path(payment_id): Path<String>,
    Json(req): Json<ConfirmFastPayRequest>,
) -> Result<Json<FastPayResponse>, HubHttpError> {
    Ok(Json(state.hub.confirm_fast_pay(
        &payment_id,
        &req.idempotency_key,
        &req.bill_hex,
    )?))
}

pub async fn serve(addr: SocketAddr, hub: Arc<HubState>) -> std::io::Result<()> {
    let app = build_router(hub);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Fast Pay hub listening");
    axum::serve(listener, app).await
}

async fn health_handler(State(state): State<AppState>) -> Json<HubHealth> {
    Json(state.hub.health())
}

async fn mainnet_readiness_handler(
    State(state): State<AppState>,
) -> Json<crate::readiness::MainnetReadinessV1> {
    Json(state.hub.mainnet_readiness().await)
}

async fn fast_pay_handler(
    State(state): State<AppState>,
    Json(req): Json<FastPayRequest>,
) -> Result<Json<FastPayResponse>, HubHttpError> {
    let resp = state.hub.settle_fast_pay(&req).await?;
    Ok(Json(resp))
}

async fn recipient_inbox_handler(
    State(state): State<AppState>,
    Path(payee): Path<String>,
) -> Json<Vec<FastPayInboxItem>> {
    Json(state.hub.recipient_inbox(&payee))
}

async fn payment_status_handler(
    State(state): State<AppState>,
    Path(payment_id): Path<String>,
) -> Result<Json<FastPayResponse>, HubHttpError> {
    let resp = state
        .hub
        .payment_status(&payment_id)
        .ok_or_else(|| HubError::NotFound(format!("payment {payment_id}")))?;
    Ok(Json(resp))
}

struct HubHttpError(HubError);

impl From<HubError> for HubHttpError {
    fn from(value: HubError) -> Self {
        Self(value)
    }
}

impl IntoResponse for HubHttpError {
    fn into_response(self) -> Response {
        let (status, public_message) = match &self.0 {
            HubError::NotFound(_) => (StatusCode::NOT_FOUND, self.0.to_string()),
            HubError::Payment(_) | HubError::Channel(_) => {
                (StatusCode::BAD_REQUEST, self.0.to_string())
            }
            HubError::Node(_) => (
                StatusCode::BAD_GATEWAY,
                "upstream full node is unavailable".to_string(),
            ),
            HubError::State(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Fast Pay Hub is unavailable".to_string(),
            ),
        };
        if status.is_server_error() {
            tracing::warn!(%status, error = %self.0, "Fast Pay Hub request failed");
        }
        let body = Json(serde_json::json!({ "error": public_message }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;

    use super::*;

    #[tokio::test]
    async fn internal_node_and_state_details_never_cross_the_http_boundary() {
        for error in [
            HubError::Node("http://127.0.0.1:8080/private".into()),
            HubError::State("/var/lib/hpay-fast-pay-hub/secret-state".into()),
        ] {
            let response = HubHttpError(error).into_response();
            assert!(response.status().is_server_error());
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            let body = String::from_utf8(body.to_vec()).unwrap();
            assert!(!body.contains("127.0.0.1"), "{body}");
            assert!(!body.contains("/var/lib"), "{body}");
        }
    }
}
