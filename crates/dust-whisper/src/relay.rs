use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use reqwest::Client;
use serde_json::json;
use tower_http::trace::TraceLayer;

use crate::crypto::{decrypt_payload, public_key_from_secret};
use crate::error::WhisperError;
use crate::http_util::ensure_success;
use crate::messenger_relay::{self, InboxAllowlist, MessengerInbox, RelayAppState};
use crate::protocol::{
    INFO_PATH, PROTOCOL_VERSION, SUBMIT_PATH, WhisperInfo, WhisperSubmitRequest,
    WhisperSubmitResponse,
};

/// Max encrypted envelope size accepted by the relay (generous for large type-4 txs).
pub const MAX_SUBMIT_BODY_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct RelayState {
    pub secret_key: [u8; 32],
    pub public_key_b64: String,
    pub default_node_url: String,
    pub http: Client,
    /// The credential the transaction door asks for. Derived from the relay's
    /// own secret key, never published, and never on the wire in an answer.
    /// See `SubmitAccess` and `submit_token_from_secret`.
    pub submit_token: String,
}

/// The header a local submitter presents at the transaction door.
pub const SUBMIT_TOKEN_HEADER: &str = "x-whisper-submit";

/// The transaction door's credential, derived from the relay's secret key.
///
/// # Why a secret and not an IP address
///
/// The door was gated on `ConnectInfo<SocketAddr>.ip().is_loopback()`, which is
/// the address of the LAST HOP and not of the submitter. Section 4 of
/// docs/RUNNING-A-RELAY.md tells an operator to keep the relay on loopback and
/// put a reverse proxy in front of it, and ships Caddy and nginx configurations
/// that both `proxy_pass http://127.0.0.1:8787`. Behind either of them every
/// submitter on earth arrives at this relay as 127.0.0.1. So in the deployment
/// this project's own documentation prescribes, an IP check let the whole
/// internet push transactions through the operator's node, from the operator's
/// address, while the screen said the door was shut. That was measured, not
/// theorised: one TCP forwarder in front of the shipped router was enough.
///
/// A secret does not have that failure mode. It is derived from the relay's
/// secret key, which lives in a file only a process on this machine with this
/// user's rights can read, so a caller who can present it has already proved
/// more than an IP address can prove and a proxy cannot launder it. It is NOT
/// the secret key and does not weaken it: it is a one-way hash of it under its
/// own domain string, so a token in a log or in a header is not a step towards
/// decrypting anything.
///
/// The loopback check is kept as well, so both have to be true. Neither is
/// sufficient and neither is being relied on alone.
pub fn submit_token_from_secret(secret: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"dust-whisper/v1/submit-token");
    hasher.update(secret);
    hex::encode(hasher.finalize())
}

/// The token for the relay whose secret key is in this file, if it is there.
///
/// Read only, and never creates one: a wallet asking this question is asking
/// "is there a relay of mine on this machine", and the answer when there is not
/// is `None`, not a new key file. `load_or_create_secret_key` is the other
/// direction and belongs to whoever is starting a relay.
pub fn local_submit_token(key_file: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(key_file).ok()?;
    let secret = parse_secret_hex(raw.trim()).ok()?;
    Some(submit_token_from_secret(&secret))
}

/// WHO MAY PUSH A TRANSACTION THROUGH THIS RELAY, WHICH IS NOT WHO MAY SEND MAIL.
///
/// `/whisper/v1/submit` takes a payload encrypted to the relay's own key,
/// decrypts it, and posts the transaction inside to the fullnode the operator
/// configured. It carries no sender address, no signature this relay checks and
/// nothing an allowlist could match on: the relay's public key is handed to
/// anybody who asks `/whisper/v1/info`, so the only credential the route has
/// ever required is being able to open the socket.
///
/// That makes it a different door from the messenger, and a door a host would
/// not know they had opened. Somebody who binds wide so a friend can collect
/// mail would otherwise also be running an open transaction submitter: any
/// machine that can route here could push arbitrary transactions at the host's
/// node, from the host's address, with the host's relay as the thing the node
/// saw. That is not what "let my friend message me" asked for, so it is denied
/// by default and denied separately.
///
/// `ThisMachineOnly` is that default. The connection has to come from this
/// machine AND the caller has to hold this relay's submit token, which is
/// derived from the key file only a local process can read - because loopback
/// on its own is not a fact about the submitter once a reverse proxy is in
/// front of the relay, and section 4 of docs/RUNNING-A-RELAY.md tells operators
/// to put one there. A connection whose peer address is not known at all counts
/// as not loopback, so a router served without connection info refuses every
/// transaction rather than accepting every transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SubmitAccess {
    /// Only a caller on this machine, holding this relay's submit token. The
    /// default, and what the wallet's own relay is always built with.
    ///
    /// Two conditions, and both have to hold. The connection has to come from
    /// this machine, AND the caller has to present `SUBMIT_TOKEN_HEADER` with
    /// the token derived from this relay's secret key. Loopback alone was the
    /// whole check once and it was not a check at all behind the reverse proxy
    /// section 4 of docs/RUNNING-A-RELAY.md tells operators to install: every
    /// caller in the world arrives from 127.0.0.1 through one of those. See
    /// `submit_token_from_secret`.
    #[default]
    ThisMachineOnly,
    /// Anybody who can reach the socket. Nothing in the wallet builds this. It
    /// is what a deliberately public relay is for, and it is the ONE state in
    /// which a stranger's transaction is forwarded to the operator's node.
    Everybody,
}

impl SubmitAccess {
    fn allows(self, from_loopback: bool, presented_token: Option<&str>, expected: &str) -> bool {
        match self {
            SubmitAccess::ThisMachineOnly => {
                from_loopback && presented_token.is_some_and(|t| constant_time_eq(t, expected))
            }
            SubmitAccess::Everybody => true,
        }
    }
}

/// Compare two tokens without letting the comparison's duration say how much of
/// one was right.
fn constant_time_eq(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// What a stranger is told when they try to broadcast through somebody's relay.
///
/// The same sentence whatever they sent, decided before the payload is
/// decrypted, so the route cannot be used to learn anything about the relay's
/// key or the operator's node either.
const SUBMIT_IS_NOT_YOURS: &str = "this relay does not accept transactions from other machines. It forwards only what is submitted from the computer it runs on, by something that can read this relay's own key file";

/// Everything this relay will serve, and to whom. Denied by default on both.
#[derive(Clone, Default)]
pub struct RelayAccess {
    /// The addresses the messenger routes carry mail for. Empty is nobody.
    pub inbox: InboxAllowlist,
    /// Who may push a transaction to the operator's node. Loopback by default.
    pub submit: SubmitAccess,
}

impl RelayAccess {
    /// A relay that serves nobody but this machine: no mail for any address,
    /// and transactions only from here.
    pub fn closed() -> Self {
        Self::default()
    }

    /// Mail for these addresses. The transaction path stays this machine only,
    /// because wanting to carry a friend's mail is not asking to broadcast
    /// their transactions.
    pub fn for_addresses(inbox: InboxAllowlist) -> Self {
        Self {
            inbox,
            submit: SubmitAccess::ThisMachineOnly,
        }
    }
}

/// A relay that carries mail for nobody and takes transactions only from this
/// machine.
///
/// This used to be a relay open to whoever could reach the socket. It is the
/// default every caller gets when it does not say who it is for, so it is the
/// one that has to be safe: a caller that forgot to name anybody now exposes
/// nobody instead of exposing everybody.
pub fn build_router(state: RelayState) -> Router {
    build_router_with(state, RelayAccess::closed())
}

/// The same relay, carrying messenger mail only for the addresses named.
///
/// The transaction path is untouched by the address list and stays loopback
/// only: see `SubmitAccess`.
pub fn build_router_for(state: RelayState, allowlist: InboxAllowlist) -> Router {
    build_router_with(state, RelayAccess::for_addresses(allowlist))
}

/// The relay, serving exactly what it was told to serve and nothing else.
pub fn build_router_with(state: RelayState, access: RelayAccess) -> Router {
    build_router_with_inbox(
        state,
        Arc::new(MessengerInbox::with_allowlist(access.inbox)),
        access.submit,
    )
}

/// The same relay, around an inbox the caller already holds.
///
/// The wallet keeps its inbox alive across a rebind so that changing where the
/// relay listens does not throw away every undelivered envelope on it. See
/// `crates/wallet-tauri-common/src/desktop_relay.rs`.
pub fn build_router_with_inbox(
    state: RelayState,
    inbox: Arc<MessengerInbox>,
    submit: SubmitAccess,
) -> Router {
    let app_state = RelayAppState {
        relay: Arc::new(state),
        inbox,
        submit,
    };
    Router::new()
        .route(INFO_PATH, get(info_handler))
        .route(SUBMIT_PATH, post(submit_handler))
        .merge(messenger_relay::messenger_routes())
        .layer(DefaultBodyLimit::max(MAX_SUBMIT_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}

/// Serve a built router with the peer address attached to every request.
///
/// Not optional. `SubmitAccess::LoopbackOnly` has to know where a connection
/// came from, and a router served without this treats every caller as remote
/// and refuses them all. That is the safe direction to fail in, and it is also
/// a relay that does not work, so every path that serves this router goes
/// through here and neither happens by accident.
pub async fn serve_router(listener: tokio::net::TcpListener, app: Router) -> std::io::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

pub async fn serve(addr: SocketAddr, state: RelayState) -> std::io::Result<()> {
    serve_with(addr, state, RelayAccess::closed()).await
}

/// Bind and serve, having said who the relay is for.
pub async fn serve_with(
    addr: SocketAddr,
    state: RelayState,
    access: RelayAccess,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    serve_listener_with(listener, state, access).await
}

pub async fn serve_listener(
    listener: tokio::net::TcpListener,
    state: RelayState,
) -> std::io::Result<()> {
    serve_listener_with(listener, state, RelayAccess::closed()).await
}

/// Serve on a socket somebody else bound, carrying mail only for the addresses
/// named. The wallet's embedded relay enters here
/// (`crates/wallet-tauri-common/src/desktop_relay.rs`).
pub async fn serve_listener_for(
    listener: tokio::net::TcpListener,
    state: RelayState,
    allowlist: InboxAllowlist,
) -> std::io::Result<()> {
    serve_listener_with(listener, state, RelayAccess::for_addresses(allowlist)).await
}

/// Serve on a socket somebody else bound, with both doors stated.
pub async fn serve_listener_with(
    listener: tokio::net::TcpListener,
    state: RelayState,
    access: RelayAccess,
) -> std::io::Result<()> {
    let listed = access.inbox.len();
    let mail_for_everybody = access.inbox.serves_everybody();
    let submit = access.submit;
    let app = build_router_with(state, access);
    let addr = listener.local_addr()?;
    tracing::info!(
        %addr,
        listed,
        mail_for_everybody,
        ?submit,
        "DUST Whisper relay listening"
    );
    serve_router(listener, app).await
}

/// The one route with no caller to allowlist, and it stays as it was.
///
/// A wallet asking whether a relay is alive is by definition asking before it
/// has established anything, so this cannot require a credential and cannot be
/// restricted by address. What a stranger who probes the port learns from it:
/// the protocol version, the relay's public key, which is a public key, and
/// which fullnode this relay forwards to. That is the operator's own
/// configuration. It is not any user's data - no address, no traffic, no hint
/// that anybody uses this relay at all - and section 6 of
/// docs/RUNNING-A-RELAY.md states it so an operator weighs it before binding.
///
/// `node_url` was withheld from non-loopback callers for one revision of this
/// change, on the reasoning that a caller who cannot submit has no use for it.
/// It was put back. A wallet pointed at a friend's relay reads this field, and
/// `relay_health` in `crates/wallet-core/src/dust_whisper.rs` reports a relay
/// that omits it as offline - so withholding it made the guest's screen call a
/// working relay dead. Concealing an operator's node URL is not worth a screen
/// that says something false, which is the failure this project keeps meeting.
async fn info_handler(State(state): State<RelayAppState>) -> Json<WhisperInfo> {
    Json(WhisperInfo {
        v: PROTOCOL_VERSION,
        pubkey: state.relay.public_key_b64.clone(),
        // Informational only. The relay always forwards to its configured node
        // URL, and only for a submitter on this machine (`SubmitAccess`).
        node_url: Some(state.relay.default_node_url.clone()),
    })
}

/// The transaction door, which is not the mail door.
///
/// Who is asking is decided first, from the kernel's own answer about the
/// connection, and before the body is even parsed. A refused caller therefore
/// learns nothing about the relay key, the operator's node, or whether their
/// payload would have decrypted: they get one fixed sentence whatever they
/// sent. See `SubmitAccess` for why this is denied by default and denied
/// separately from the address allowlist.
async fn submit_handler(
    State(state): State<RelayAppState>,
    request: Request,
) -> Json<WhisperSubmitResponse> {
    let from_loopback = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| peer.ip().is_loopback())
        .unwrap_or(false);
    let presented = request
        .headers()
        .get(SUBMIT_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok());
    if !state
        .submit
        .allows(from_loopback, presented, &state.relay.submit_token)
    {
        tracing::warn!("refused a transaction submitted from another machine");
        return Json(WhisperSubmitResponse {
            ret: 1,
            err: Some(SUBMIT_IS_NOT_YOURS.to_string()),
            message: None,
            hash: None,
        });
    }
    let request = match Json::<WhisperSubmitRequest>::from_request(request, &state).await {
        Ok(Json(request)) => request,
        Err(rejection) => {
            return Json(WhisperSubmitResponse {
                ret: 1,
                err: Some(rejection.body_text()),
                message: None,
                hash: None,
            });
        }
    };
    match forward_submit(&state.relay, &request).await {
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

    // Always use operator-configured node URL. never trust client-supplied targets (SSRF).
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
    let public_key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pk);
    RelayState {
        submit_token: submit_token_from_secret(&secret),
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

pub fn load_or_create_secret_key(path: &Path) -> Result<[u8; 32], String> {
    if path.exists() {
        let raw = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
        return parse_secret_hex(raw.trim());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let (secret, _) = crate::crypto::generate_relay_keypair();
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    writeln!(file, "{}", hex::encode(secret)).map_err(|error| error.to_string())?;
    Ok(secret)
}

pub fn relay_info_json(state: &RelayState) -> serde_json::Value {
    json!({
        "v": PROTOCOL_VERSION,
        "pubkey": state.public_key_b64,
        "node_url": state.default_node_url,
    })
}
