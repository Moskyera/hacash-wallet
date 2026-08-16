use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::{HeaderValue, StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, extract::DefaultBodyLimit};
use tower_http::trace::TraceLayer;

use crate::api::{
    ConfirmFastPayRequest, FastPayInboxItem, FastPayRequest, FastPayResponse, HubHealth,
};
use crate::error::HubError;
use crate::hvm_channel::HvmChannelBillV1;
use crate::hvm_ledger::{HvmChannelStatusV1, HvmPaymentRequestV1, HvmPaymentStatusV1};
use crate::hvm_registry::HvmRegistryBillV2;
use crate::hvm_registry_ledger::{
    HvmRegistryChannelStatusV2, HvmRegistryPaymentRequestV2, HvmRegistryPaymentStatusV2,
};
use crate::l1_channel::{L1ChannelOpenRequest, L1ChannelOpenStatusResponse};
use crate::l1_channel_close::{L1ChannelCloseRequest, L1ChannelCloseResponse};
use crate::state::HubState;

pub const MAX_HUB_REQUEST_BODY_BYTES: usize = 64 * 1024;

const OPEN_REQUEST_WINDOW_SECONDS: u64 = 60;
const PUBLIC_READINESS_CACHE_TTL: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_PUBLIC_READINESS_REQUESTS: usize = 8;
const MAX_CONCURRENT_MUTATION_REQUESTS: usize = 32;
const MAX_OPEN_REQUESTS_PER_PEER_WINDOW: usize = 16;
const MAX_MUTATION_REQUESTS_PER_PEER_WINDOW: usize = 120;
const MAX_TRACKED_OPEN_PEERS: usize = 4096;

#[derive(Default)]
struct PeerOpenAdmission {
    recent: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl PeerOpenAdmission {
    fn check(&self, peer: IpAddr, limit: usize) -> Result<(), HubError> {
        let peer = normalize_peer_ip(peer);
        let now = Instant::now();
        let window = Duration::from_secs(OPEN_REQUEST_WINDOW_SECONDS);
        let mut guard = self
            .recent
            .lock()
            .map_err(|_| HubError::State("peer admission lock poisoned".into()))?;
        guard.retain(|_, requests| {
            while requests
                .front()
                .is_some_and(|seen| now.duration_since(*seen) >= window)
            {
                requests.pop_front();
            }
            !requests.is_empty()
        });
        if !guard.contains_key(&peer) && guard.len() >= MAX_TRACKED_OPEN_PEERS {
            return Err(HubError::Admission(
                "channel-open peer capacity is temporarily exhausted".into(),
            ));
        }
        let requests = guard.entry(peer).or_default();
        if requests.len() >= limit {
            return Err(HubError::Admission(
                "channel-open request rate exceeded".into(),
            ));
        }
        requests.push_back(now);
        Ok(())
    }
}

fn normalize_peer_ip(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        other => other,
    }
}

/// `/v1/health` measures its mainnet guarantees from a live fullnode probe, so
/// it carries the same cache and admission budget as the readiness endpoint
/// rather than proxying unbounded load to the node. The TTL is far inside the
/// 60-second readiness window, so a cached answer is never staler than the
/// evidence the money gate itself accepts.
#[derive(Default)]
struct PublicHealthCache {
    snapshot: tokio::sync::Mutex<Option<(Instant, HubHealth)>>,
}

impl PublicHealthCache {
    async fn get_or_refresh<F, Fut>(&self, refresh: F) -> HubHealth
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = HubHealth>,
    {
        let mut guard = self.snapshot.lock().await;
        if let Some((captured_at, snapshot)) = guard.as_ref()
            && captured_at.elapsed() < PUBLIC_READINESS_CACHE_TTL
        {
            return snapshot.clone();
        }
        let snapshot = refresh().await;
        *guard = Some((Instant::now(), snapshot.clone()));
        snapshot
    }
}

#[derive(Default)]
struct PublicReadinessCache {
    snapshot: tokio::sync::Mutex<Option<(Instant, crate::readiness::MainnetReadinessV1)>>,
}

impl PublicReadinessCache {
    async fn get_or_refresh<F, Fut>(&self, refresh: F) -> crate::readiness::MainnetReadinessV1
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = crate::readiness::MainnetReadinessV1>,
    {
        let mut guard = self.snapshot.lock().await;
        if let Some((captured_at, snapshot)) = guard.as_ref()
            && captured_at.elapsed() < PUBLIC_READINESS_CACHE_TTL
        {
            return snapshot.clone();
        }
        let snapshot = refresh().await;
        *guard = Some((Instant::now(), snapshot.clone()));
        snapshot
    }
}

#[derive(Clone)]
pub struct AppState {
    pub hub: Arc<HubState>,
    peer_open_admission: Arc<PeerOpenAdmission>,
    peer_mutation_admission: Arc<PeerOpenAdmission>,
    global_mutation_admission: Arc<tokio::sync::Semaphore>,
    public_readiness_cache: Arc<PublicReadinessCache>,
    public_health_cache: Arc<PublicHealthCache>,
    public_readiness_admission: Arc<tokio::sync::Semaphore>,
    trusted_proxy: Option<IpAddr>,
}

pub fn build_router(hub: Arc<HubState>) -> Router {
    build_router_with_trusted_proxy(hub, None)
}

pub fn build_router_with_trusted_proxy(
    hub: Arc<HubState>,
    trusted_proxy: Option<IpAddr>,
) -> Router {
    Router::new()
        .route("/v1/health", get(health_handler))
        .route("/v1/readiness/mainnet", get(mainnet_readiness_handler))
        .route("/v1/fast-pay", post(fast_pay_handler))
        .route("/v1/hvm/payment", post(hvm_payment_handler))
        .route(
            "/v1/hvm/payment/{operation_id}",
            get(hvm_payment_status_handler),
        )
        .route(
            "/v1/hvm/channel/{binding_commitment}",
            get(hvm_channel_status_handler),
        )
        .route(
            "/v2/hvm-registry/payment",
            post(hvm_registry_payment_handler),
        )
        .route(
            "/v2/hvm-registry/payment/{operation_id}",
            get(hvm_registry_payment_status_handler),
        )
        .route(
            "/v2/hvm-registry/channel/{binding_commitment}",
            get(hvm_registry_channel_status_handler),
        )
        .route("/v1/l1/channel/open", post(channel_open_handler))
        .route("/v1/l1/channel/close", post(channel_close_handler))
        .route("/v1/fast-pay/inbox/{payee}", get(recipient_inbox_handler))
        .route("/v1/fast-pay/{payment_id}", get(payment_status_handler))
        .route(
            "/v1/fast-pay/{payment_id}/confirm",
            post(confirm_fast_pay_handler),
        )
        .layer(DefaultBodyLimit::max(MAX_HUB_REQUEST_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            hub,
            peer_open_admission: Arc::new(PeerOpenAdmission::default()),
            peer_mutation_admission: Arc::new(PeerOpenAdmission::default()),
            global_mutation_admission: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_MUTATION_REQUESTS,
            )),
            public_readiness_cache: Arc::new(PublicReadinessCache::default()),
            public_health_cache: Arc::new(PublicHealthCache::default()),
            public_readiness_admission: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_PUBLIC_READINESS_REQUESTS,
            )),
            trusted_proxy: trusted_proxy.map(normalize_peer_ip),
        })
}

async fn confirm_fast_pay_handler(
    State(state): State<AppState>,
    Path(payment_id): Path<String>,
    PeerIp(peer): PeerIp,
    Json(req): Json<ConfirmFastPayRequest>,
) -> Result<Json<FastPayResponse>, HubHttpError> {
    let _global_permit = acquire_global_mutation_permit(&state)?;
    state
        .peer_mutation_admission
        .check(peer, MAX_MUTATION_REQUESTS_PER_PEER_WINDOW)?;
    Ok(Json(state.hub.confirm_fast_pay(
        &payment_id,
        &req.idempotency_key,
        &req.bill_hex,
    )?))
}

pub async fn serve(addr: SocketAddr, hub: Arc<HubState>) -> std::io::Result<()> {
    serve_with_trusted_proxy(addr, hub, None).await
}

pub async fn serve_with_trusted_proxy(
    addr: SocketAddr,
    hub: Arc<HubState>,
    trusted_proxy: Option<IpAddr>,
) -> std::io::Result<()> {
    let app = build_router_with_trusted_proxy(hub, trusted_proxy);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Fast Pay hub listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

struct PeerIp(IpAddr);

impl FromRequestParts<AppState> for PeerIp {
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let socket_peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), |peer| {
                normalize_peer_ip(peer.0.ip())
            });
        let forwarded = parts.headers.get("x-real-ip").cloned();
        let trusted_proxy = state.trusted_proxy;
        async move {
            effective_peer_ip(socket_peer, trusted_proxy, forwarded.as_ref())
                .map(Self)
                .ok_or(StatusCode::BAD_REQUEST)
        }
    }
}

fn effective_peer_ip(
    socket_peer: IpAddr,
    trusted_proxy: Option<IpAddr>,
    x_real_ip: Option<&HeaderValue>,
) -> Option<IpAddr> {
    let socket_peer = normalize_peer_ip(socket_peer);
    if trusted_proxy.map(normalize_peer_ip) != Some(socket_peer) {
        return Some(socket_peer);
    }
    let raw = x_real_ip?.to_str().ok()?;
    if raw.trim() != raw || raw.contains(',') {
        return None;
    }
    raw.parse::<IpAddr>().ok().map(normalize_peer_ip)
}
async fn health_handler(State(state): State<AppState>) -> Result<Json<HubHealth>, Response> {
    let _permit = state
        .public_readiness_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| public_readiness_busy_response())?;
    let snapshot = state
        .public_health_cache
        .get_or_refresh(|| std::future::ready(state.hub.health()))
        .await;
    Ok(Json(snapshot))
}

async fn mainnet_readiness_handler(
    State(state): State<AppState>,
) -> Result<Json<crate::readiness::MainnetReadinessV1>, Response> {
    let _permit = state
        .public_readiness_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| public_readiness_busy_response())?;
    let snapshot = state
        .public_readiness_cache
        .get_or_refresh(|| state.hub.mainnet_readiness())
        .await;
    Ok(Json(snapshot))
}

fn public_readiness_busy_response() -> Response {
    let mut response = HubHttpError(HubError::Admission(
        "public readiness concurrency is temporarily exhausted".into(),
    ))
    .into_response();
    response.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        HeaderValue::from_static("1"),
    );
    response
}

async fn channel_open_handler(
    State(state): State<AppState>,
    PeerIp(peer): PeerIp,
    Json(request): Json<L1ChannelOpenRequest>,
) -> Result<Json<L1ChannelOpenStatusResponse>, HubHttpError> {
    let _global_permit = acquire_global_mutation_permit(&state)?;
    state
        .peer_mutation_admission
        .check(peer, MAX_MUTATION_REQUESTS_PER_PEER_WINDOW)?;
    if !state.hub.is_exact_existing_channel_open(&request)? {
        state
            .peer_open_admission
            .check(peer, MAX_OPEN_REQUESTS_PER_PEER_WINDOW)?;
    }
    Ok(Json(state.hub.open_channel(&request).await?))
}
async fn channel_close_handler(
    State(state): State<AppState>,
    PeerIp(peer): PeerIp,
    Json(request): Json<L1ChannelCloseRequest>,
) -> Result<Json<L1ChannelCloseResponse>, HubHttpError> {
    let _global_permit = acquire_global_mutation_permit(&state)?;
    state
        .peer_mutation_admission
        .check(peer, MAX_MUTATION_REQUESTS_PER_PEER_WINDOW)?;
    Ok(Json(state.hub.close_channel(&request).await?))
}

async fn fast_pay_handler(
    State(state): State<AppState>,
    PeerIp(peer): PeerIp,
    Json(req): Json<FastPayRequest>,
) -> Result<Json<FastPayResponse>, HubHttpError> {
    let _global_permit = acquire_global_mutation_permit(&state)?;
    state
        .peer_mutation_admission
        .check(peer, MAX_MUTATION_REQUESTS_PER_PEER_WINDOW)?;
    let resp = state.hub.settle_fast_pay(&req).await?;
    Ok(Json(resp))
}

async fn hvm_payment_handler(
    State(state): State<AppState>,
    PeerIp(peer): PeerIp,
    Json(request): Json<HvmPaymentRequestV1>,
) -> Result<Json<HvmChannelBillV1>, HubHttpError> {
    let _global_permit = acquire_global_mutation_permit(&state)?;
    state
        .peer_mutation_admission
        .check(peer, MAX_MUTATION_REQUESTS_PER_PEER_WINDOW)?;
    Ok(Json(
        state
            .hub
            .cosign_hvm_payment(request, crate::node::now_unix())
            .await?,
    ))
}

async fn hvm_payment_status_handler(
    State(state): State<AppState>,
    Path(operation_id): Path<String>,
) -> Result<Json<HvmPaymentStatusV1>, HubHttpError> {
    Ok(Json(state.hub.hvm_payment_status(&operation_id)?))
}

async fn hvm_channel_status_handler(
    State(state): State<AppState>,
    Path(binding_commitment): Path<String>,
) -> Result<Json<HvmChannelStatusV1>, HubHttpError> {
    Ok(Json(state.hub.hvm_channel_status(&binding_commitment)?))
}

async fn hvm_registry_payment_handler(
    State(state): State<AppState>,
    PeerIp(peer): PeerIp,
    Json(request): Json<HvmRegistryPaymentRequestV2>,
) -> Result<Json<HvmRegistryBillV2>, HubHttpError> {
    let _global_permit = acquire_global_mutation_permit(&state)?;
    state
        .peer_mutation_admission
        .check(peer, MAX_MUTATION_REQUESTS_PER_PEER_WINDOW)?;
    Ok(Json(
        state
            .hub
            .cosign_hvm_registry_payment(request, crate::node::now_unix())
            .await?,
    ))
}

async fn hvm_registry_payment_status_handler(
    State(state): State<AppState>,
    Path(operation_id): Path<String>,
) -> Result<Json<HvmRegistryPaymentStatusV2>, HubHttpError> {
    Ok(Json(state.hub.hvm_registry_payment_status(&operation_id)?))
}

async fn hvm_registry_channel_status_handler(
    State(state): State<AppState>,
    Path(binding_commitment): Path<String>,
) -> Result<Json<HvmRegistryChannelStatusV2>, HubHttpError> {
    Ok(Json(
        state.hub.hvm_registry_channel_status(&binding_commitment)?,
    ))
}

fn acquire_global_mutation_permit(
    state: &AppState,
) -> Result<tokio::sync::OwnedSemaphorePermit, HubHttpError> {
    state
        .global_mutation_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            HubHttpError(HubError::Admission(
                "global mutation capacity is exhausted".into(),
            ))
        })
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
            HubError::Admission(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                "Fast Pay Hub admission limit reached".to_string(),
            ),
        };
        if status.is_server_error() {
            tracing::warn!(%status, error = %self.0, "Fast Pay Hub request failed");
        }
        let body = Json(serde_json::json!({ "error": public_message }));
        let mut response = (status, body).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_static("60"),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn registry_public_routes_expose_payments_but_not_owner_or_watchtower_controls() {
        let source = include_str!("server.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production server source");
        /*
        assert!(source.contains("\/v2/hvm-registry/payment\"));
        assert!(source.contains("\/v2/hvm-registry/channel/{binding_commitment}\"));
        */
        assert!(source.contains("/v2/hvm-registry/payment"));
        assert!(source.contains("/v2/hvm-registry/channel/{binding_commitment}"));
        for forbidden in [
            "/v2/hvm-registry/activate",
            "/v2/hvm-registry/watchtower",
            "/v2/hvm-registry/lease",
            "/v2/hvm-registry/reconcile",
        ] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
    }

    fn failed_readiness_snapshot() -> crate::readiness::MainnetReadinessV1 {
        crate::readiness::MainnetReadinessV1::evaluate(
            "development",
            0,
            0,
            true,
            false,
            false,
            Err(HubError::Node("test capability failure".into())),
        )
    }

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
    #[tokio::test]
    async fn admission_error_is_sanitized_and_includes_retry_after() {
        let response =
            HubHttpError(HubError::Admission("private quota details".into())).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(axum::http::header::RETRY_AFTER),
            Some(&HeaderValue::from_static("60"))
        );
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("private quota details"), "{body}");
        assert!(body.contains("admission limit reached"), "{body}");
    }

    #[tokio::test]
    async fn public_readiness_cache_is_single_flight_and_refreshes_only_after_expiry() {
        let cache = Arc::new(PublicReadinessCache::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let expected = failed_readiness_snapshot();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..MAX_CONCURRENT_PUBLIC_READINESS_REQUESTS {
            let cache = cache.clone();
            let calls = calls.clone();
            let expected = expected.clone();
            tasks.spawn(async move {
                cache
                    .get_or_refresh(|| async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        expected
                    })
                    .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(result.unwrap(), expected);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let cached = cache
            .get_or_refresh(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                failed_readiness_snapshot()
            })
            .await;
        assert_eq!(cached, expected);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        {
            let mut guard = cache.snapshot.lock().await;
            guard.as_mut().unwrap().0 = Instant::now() - PUBLIC_READINESS_CACHE_TTL;
        }
        let refreshed_expected = failed_readiness_snapshot();
        let refreshed = cache
            .get_or_refresh(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                refreshed_expected.clone()
            })
            .await;
        assert_eq!(refreshed, refreshed_expected);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn expired_public_success_is_replaced_by_fail_closed_probe_result() {
        let cache = PublicReadinessCache::default();
        let mut positive = failed_readiness_snapshot();
        positive.mainnet_detected = Some(true);
        positive.payments_enabled = true;
        positive.blockers.clear();
        let cached = cache.get_or_refresh(|| async { positive.clone() }).await;
        assert!(cached.payments_enabled);

        {
            let mut guard = cache.snapshot.lock().await;
            guard.as_mut().unwrap().0 = Instant::now() - PUBLIC_READINESS_CACHE_TTL;
        }
        let failed = failed_readiness_snapshot();
        let refreshed = cache.get_or_refresh(|| async { failed.clone() }).await;
        assert!(!refreshed.payments_enabled);
        assert_eq!(refreshed.mainnet_detected, None);
        assert_eq!(refreshed, failed);
    }

    #[tokio::test]
    async fn cancelled_public_readiness_probe_releases_the_single_flight_lock() {
        let cache = Arc::new(PublicReadinessCache::default());
        let entered = Arc::new(tokio::sync::Notify::new());
        let never = Arc::new(tokio::sync::Notify::new());
        let task = {
            let cache = cache.clone();
            let entered = entered.clone();
            let never = never.clone();
            tokio::spawn(async move {
                cache
                    .get_or_refresh(|| async move {
                        entered.notify_one();
                        never.notified().await;
                        failed_readiness_snapshot()
                    })
                    .await
            })
        };
        entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let recovered = tokio::time::timeout(
            Duration::from_millis(100),
            cache.get_or_refresh(|| async { failed_readiness_snapshot() }),
        )
        .await
        .expect("cancelled leader must release the cache lock");
        assert!(!recovered.payments_enabled);
    }

    #[tokio::test]
    async fn public_readiness_concurrency_is_bounded_and_busy_response_is_short_lived() {
        let admission = Arc::new(tokio::sync::Semaphore::new(
            MAX_CONCURRENT_PUBLIC_READINESS_REQUESTS,
        ));
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_PUBLIC_READINESS_REQUESTS {
            permits.push(admission.clone().try_acquire_owned().unwrap());
        }
        assert!(admission.clone().try_acquire_owned().is_err());

        let response = public_readiness_busy_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(axum::http::header::RETRY_AFTER),
            Some(&HeaderValue::from_static("1"))
        );
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("concurrency"), "{body}");
        assert!(body.contains("admission limit reached"), "{body}");

        drop(permits);
        assert!(admission.try_acquire_owned().is_ok());
    }
    #[test]
    fn untrusted_peer_cannot_spoof_x_real_ip() {
        let socket_peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let claimed = HeaderValue::from_static("198.51.100.8");
        assert_eq!(
            effective_peer_ip(socket_peer, None, Some(&claimed)),
            Some(socket_peer)
        );
        assert_eq!(
            effective_peer_ip(
                socket_peer,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))),
                Some(&claimed)
            ),
            Some(socket_peer)
        );
    }

    #[test]
    fn exact_trusted_proxy_may_supply_one_strict_client_ip() {
        let proxy = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        let claimed = HeaderValue::from_static("198.51.100.8");
        assert_eq!(
            effective_peer_ip(proxy, Some(proxy), Some(&claimed)),
            Some(client)
        );
    }

    #[test]
    fn trusted_proxy_header_is_required_and_rejects_lists_or_whitespace() {
        let proxy = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(effective_peer_ip(proxy, Some(proxy), None), None);
        for value in [
            " 198.51.100.8",
            "198.51.100.8 ",
            "198.51.100.8, 203.0.113.5",
            "not-an-ip",
        ] {
            let claimed = HeaderValue::from_str(value).unwrap();
            assert_eq!(effective_peer_ip(proxy, Some(proxy), Some(&claimed)), None);
        }
    }

    #[test]
    fn peer_open_limit_is_per_socket_ip_and_fail_closed_at_the_boundary() {
        let admission = PeerOpenAdmission::default();
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
        for _ in 0..MAX_OPEN_REQUESTS_PER_PEER_WINDOW {
            admission
                .check(first, MAX_OPEN_REQUESTS_PER_PEER_WINDOW)
                .unwrap();
        }
        assert!(matches!(
            admission.check(first, MAX_OPEN_REQUESTS_PER_PEER_WINDOW),
            Err(HubError::Admission(_))
        ));
        admission
            .check(second, MAX_OPEN_REQUESTS_PER_PEER_WINDOW)
            .unwrap();

        let mapped = IpAddr::V6(
            first
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .unwrap()
                .to_ipv6_mapped(),
        );
        assert!(matches!(
            admission.check(mapped, MAX_OPEN_REQUESTS_PER_PEER_WINDOW),
            Err(HubError::Admission(_))
        ));
    }
}
