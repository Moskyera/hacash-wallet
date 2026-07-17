//! Local MoneyNex bridge for desktop browser (hacd.it via Chrome/Edge extension).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{Method, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use hacash_wallet_core::WalletService;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

use crate::dapp_approval::{ApprovalDecision, DappApprovalQueue};
use crate::state::AppState;

pub const DAPP_BRIDGE_PORT: u16 = 9477;
pub const DAPP_BRIDGE_ADDR: &str = "127.0.0.1:9477";
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(45);

pub struct DappBridgeHandle {
    server: Mutex<Option<tokio::task::JoinHandle<()>>>,
    keepalive: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DappBridgeHandle {
    pub fn new() -> Self {
        Self {
            server: Mutex::new(None),
            keepalive: Mutex::new(None),
        }
    }
}

#[derive(Clone)]
struct BridgeState {
    wallet: Arc<Mutex<WalletService>>,
    approval: Arc<DappApprovalQueue>,
}

#[derive(Debug, Deserialize)]
struct OriginBody {
    origin: String,
}

#[derive(Debug, Deserialize)]
struct TransferBody {
    origin: String,
    txobj: String,
}

#[derive(Debug, Deserialize)]
struct SignBody {
    origin: String,
    txbody: String,
    #[serde(default)]
    autosubmit: bool,
}

pub async fn stop_dapp_bridge(state: &AppState) -> Result<(), String> {
    let mut server = state.dapp_bridge.server.lock().await;
    if let Some(handle) = server.take() {
        handle.abort();
    }
    let mut keepalive = state.dapp_bridge.keepalive.lock().await;
    if let Some(handle) = keepalive.take() {
        handle.abort();
    }
    Ok(())
}

pub async fn start_dapp_bridge(state: &AppState) -> Result<u16, String> {
    let mut server_guard = state.dapp_bridge.server.lock().await;
    if server_guard.is_some() {
        return Ok(DAPP_BRIDGE_PORT);
    }

    let wallet = state.inner.clone();
    let approval = state.dapp_approval.clone();
    let bridge_state = BridgeState {
        wallet: wallet.clone(),
        approval,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/status", get(status_route))
        .route("/v1/heartbeat", post(heartbeat_route))
        .route("/v1/connect", post(connect_route))
        .route("/v1/wallet", post(wallet_route))
        .route("/v1/transfer", post(transfer_route))
        .route("/v1/signtx", post(sign_route))
        .route("/v1/chain", post(chain_route))
        .layer(cors)
        .with_state(bridge_state);

    let addr: SocketAddr = DAPP_BRIDGE_ADDR
        .parse()
        .map_err(|e| format!("invalid bridge listen address: {e}"))?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("dapp bridge bind failed on {DAPP_BRIDGE_ADDR}: {e}"))?;

    let server_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::warn!("dapp bridge server stopped: {e}");
        }
    });

    let keepalive_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let mut svc = wallet.lock().await;
            svc.dapp_keepalive_bump();
        }
    });

    *server_guard = Some(server_handle);
    let mut keepalive_guard = state.dapp_bridge.keepalive.lock().await;
    *keepalive_guard = Some(keepalive_handle);

    tracing::info!("HACD browser bridge listening on http://{DAPP_BRIDGE_ADDR}");
    Ok(DAPP_BRIDGE_PORT)
}

pub async fn bridge_status(state: &AppState) -> Result<Value, String> {
    let running = state.dapp_bridge.server.lock().await.is_some();
    let wallet = state.inner.lock().await;
    let locked = wallet.status().locked;
    let address = wallet.status().address;
    let dapp_active = wallet.dapp_session_active();
    drop(wallet);
    Ok(json!({
        "running": running,
        "port": DAPP_BRIDGE_PORT,
        "url": format!("http://{DAPP_BRIDGE_ADDR}"),
        "wallet_locked": locked,
        "dapp_session_active": dapp_active,
        "address": address
    }))
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true, "service": "hacash-dapp-bridge" }))
}

async fn status_route(State(st): State<BridgeState>) -> Json<Value> {
    let svc = st.wallet.lock().await;
    let status = svc.status();
    Json(json!({
        "running": true,
        "wallet_locked": status.locked,
        "dapp_session_active": svc.dapp_session_active(),
        "address": status.address
    }))
}

async fn heartbeat_route(
    State(st): State<BridgeState>,
    Json(body): Json<OriginBody>,
) -> Json<Value> {
    match bridge_heartbeat(&st, &body.origin).await {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "ok": false, "err": e })),
    }
}

async fn connect_route(State(st): State<BridgeState>, Json(body): Json<OriginBody>) -> Json<Value> {
    match bridge_connect(&st, &body.origin).await {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "err": e, "ret": 1 })),
    }
}

async fn wallet_route(State(st): State<BridgeState>, Json(body): Json<OriginBody>) -> Json<Value> {
    match bridge_wallet(&st, &body.origin).await {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "err": e, "ret": 1 })),
    }
}

async fn transfer_route(
    State(st): State<BridgeState>,
    Json(body): Json<TransferBody>,
) -> Json<Value> {
    match bridge_transfer(&st, &body.origin, &body.txobj).await {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "err": e, "ret": 1 })),
    }
}

async fn sign_route(State(st): State<BridgeState>, Json(body): Json<SignBody>) -> Json<Value> {
    match bridge_sign(&st, &body.origin, &body.txbody, body.autosubmit).await {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "err": e, "ret": 1 })),
    }
}

async fn chain_route(State(st): State<BridgeState>, Json(body): Json<OriginBody>) -> Json<Value> {
    let mut svc = st.wallet.lock().await;
    if svc.dapp_session_is_authorized(&body.origin) {
        svc.dapp_keepalive_bump();
    }
    match svc.dapp_chain_status(&body.origin, Some(0)) {
        Ok(v) => Json(v),
        Err(e) => Json(json!({ "err": e.to_string(), "ret": 1 })),
    }
}

async fn bridge_heartbeat(st: &BridgeState, origin: &str) -> Result<Value, String> {
    let mut svc = st.wallet.lock().await;
    svc.dapp_heartbeat(origin).map_err(|e| e.to_string())
}

async fn bridge_connect(st: &BridgeState, origin: &str) -> Result<Value, String> {
    await_user_approval(
        &st.approval,
        origin,
        "connect",
        "Connect to app",
        &format!("{origin} wants to connect to your wallet."),
        "The app can request transaction signatures after you accept.",
    )
    .await?;
    let mut svc = st.wallet.lock().await;
    svc.dapp_connect(origin).map_err(|e| e.to_string())
}

async fn bridge_wallet(st: &BridgeState, origin: &str) -> Result<Value, String> {
    let mut svc = st.wallet.lock().await;
    svc.dapp_wallet(origin).map_err(|e| e.to_string())
}

async fn bridge_transfer(st: &BridgeState, origin: &str, txobj: &str) -> Result<Value, String> {
    let detail =
        hacash_wallet_core::dapp::describe_txobj_for_approval(txobj).map_err(|e| e.to_string())?;
    await_user_approval(
        &st.approval,
        origin,
        "transfer",
        "Approve dApp transaction",
        "Review every action before the wallet signs and broadcasts it.",
        &detail,
    )
    .await?;
    let mut svc = st.wallet.lock().await;
    svc.dapp_transfer(origin, txobj)
        .await
        .map_err(|e| e.to_string())
}

async fn bridge_sign(
    st: &BridgeState,
    origin: &str,
    txbody: &str,
    autosubmit: bool,
) -> Result<Value, String> {
    let canonical =
        hacash_wallet_core::tx_binding::decode_transaction(txbody).map_err(|e| e.to_string())?;
    let title = if autosubmit {
        "Approve signing and broadcast"
    } else {
        "Approve transaction signature"
    };
    await_user_approval(
        &st.approval,
        origin,
        "sign",
        title,
        "The wallet will sign exactly the decoded transaction shown below.",
        &canonical.approval_summary(),
    )
    .await?;
    let mut svc = st.wallet.lock().await;
    svc.dapp_sign_tx(origin, txbody, autosubmit)
        .await
        .map_err(|e| e.to_string())
}

#[allow(dead_code)]
fn truncate_detail(text: &str, max: usize) -> String {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() <= max {
        clean
    } else {
        format!("{}…", &clean[..max])
    }
}

async fn await_user_approval(
    approval: &DappApprovalQueue,
    origin: &str,
    kind: &str,
    title: &str,
    summary: &str,
    detail: &str,
) -> Result<(), String> {
    match approval
        .request(
            origin,
            kind,
            title,
            summary,
            detail,
            Duration::from_secs(120),
        )
        .await
    {
        Ok(ApprovalDecision::Approved) => Ok(()),
        Ok(ApprovalDecision::Rejected(reason)) => Err(format!("declined: {reason}")),
        Err(e) => Err(e),
    }
}
