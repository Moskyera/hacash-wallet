use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::trace::TraceLayer;

use crate::api::{
    ConfirmFastPayRequest, FastPayInboxItem, FastPayRequest, FastPayResponse, HubHealth,
};
use crate::error::HubError;
use crate::state::HubState;

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<HubState>,
}

pub fn build_router(hub: Arc<HubState>) -> Router {
    Router::new()
        .route("/v1/health", get(health_handler))
        .route("/v1/fast-pay", post(fast_pay_handler))
        .route("/v1/fast-pay/inbox/{payee}", get(recipient_inbox_handler))
        .route("/v1/fast-pay/{payment_id}", get(payment_status_handler))
        .route(
            "/v1/fast-pay/{payment_id}/confirm",
            post(confirm_fast_pay_handler),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(AppState { hub })
}

async fn confirm_fast_pay_handler(
    State(state): State<AppState>,
    Path(payment_id): Path<String>,
    Json(req): Json<ConfirmFastPayRequest>,
) -> Result<Json<FastPayResponse>, HubHttpError> {
    Ok(Json(
        state.hub.confirm_fast_pay(&payment_id, &req.bill_hex)?,
    ))
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

async fn fast_pay_handler(
    State(state): State<AppState>,
    Json(req): Json<FastPayRequest>,
) -> Result<Json<FastPayResponse>, HubHttpError> {
    let resp = state
        .hub
        .settle_fast_pay(&req.payer, &req.payee, &req.amount, &req.channel_id)
        .await?;
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
        let status = match &self.0 {
            HubError::NotFound(_) => StatusCode::NOT_FOUND,
            HubError::Payment(_) | HubError::Channel(_) => StatusCode::BAD_REQUEST,
            HubError::Node(_) => StatusCode::BAD_GATEWAY,
            HubError::State(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(serde_json::json!({ "error": self.0.to_string() }));
        (status, body).into_response()
    }
}
