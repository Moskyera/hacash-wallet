use std::sync::OnceLock;
use std::time::Duration;

pub(crate) const WALLET_USER_AGENT: &str = concat!("HacashWallet/", env!("CARGO_PKG_VERSION"));
pub(crate) const NODE_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
pub(crate) const NODE_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Shared transport discipline for native wallet HTTP clients.
///
/// The client owns connection pooling, TLS, no-proxy policy, application
/// identity, timeouts, and a no-redirect policy. A node response must never
/// move a wallet request or signed payload to a different origin.
pub(crate) fn shared_http_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(build_async_http_client)
        .as_ref()
        .map_err(Clone::clone)
}

fn build_async_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .pool_max_idle_per_host(8)
        .tcp_keepalive(Duration::from_secs(60))
        .connect_timeout(NODE_CONNECT_TIMEOUT)
        .timeout(NODE_REQUEST_TIMEOUT)
        .user_agent(WALLET_USER_AGENT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("wallet HTTP client setup failed: {error}"))
}

#[cfg(target_os = "android")]
pub(crate) fn blocking_http_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .connect_timeout(NODE_CONNECT_TIMEOUT)
        .timeout(NODE_REQUEST_TIMEOUT)
        .user_agent(WALLET_USER_AGENT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("Android wallet HTTP client setup failed: {error}"))
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::response::IntoResponse;
    use axum::routing::get;

    use super::*;

    #[test]
    fn node_timeout_budget_is_bounded_for_interactive_wallet_calls() {
        assert_eq!(NODE_CONNECT_TIMEOUT, Duration::from_secs(8));
        assert_eq!(NODE_REQUEST_TIMEOUT, Duration::from_secs(20));
        assert!(NODE_CONNECT_TIMEOUT < NODE_REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn shared_client_sets_dynamic_identity_and_never_follows_redirects() {
        let app = Router::new()
            .route(
                "/redirect",
                get(|headers: HeaderMap| async move {
                    assert_eq!(
                        headers
                            .get(header::USER_AGENT)
                            .and_then(|value| value.to_str().ok()),
                        Some(WALLET_USER_AGENT)
                    );
                    (StatusCode::FOUND, [(header::LOCATION, "/target")]).into_response()
                }),
            )
            .route("/target", get(|| async { StatusCode::IM_A_TEAPOT }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind transport test server");
        let address = listener.local_addr().expect("transport test address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve transport test");
        });

        let response = shared_http_client()
            .expect("shared client")
            .get(format!("http://{address}/redirect"))
            .send()
            .await
            .expect("redirect response");
        assert_eq!(response.status(), StatusCode::FOUND);
        server.abort();
    }
}
