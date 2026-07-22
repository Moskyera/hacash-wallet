use std::future::Future;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::http_client::shared_http_client;

const FRESH_TTL: Duration = Duration::from_secs(2 * 60);
const MAX_STALE_AGE: Duration = Duration::from_secs(30 * 60);
const FAILURE_RETRY_DELAY: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
const TOTAL_REFRESH_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

type RefreshError = (String, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PriceSource {
    #[serde(rename = "coinpaprika")]
    CoinPaprika,
    #[serde(rename = "coingecko")]
    CoinGecko,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpotPrices {
    pub hac_usd: f64,
    pub hacd_usd: f64,
    pub btc_usd: f64,
    pub source: PriceSource,
    pub stale: bool,
    pub observed_at_utc: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct PriceQuote {
    hac_usd: f64,
    hacd_usd: f64,
    btc_usd: f64,
    source: PriceSource,
}

#[derive(Debug, Clone)]
struct CachedPriceQuote {
    quote: PriceQuote,
    observed_at_utc: String,
    stored_at: Instant,
}

#[derive(Debug, Clone)]
struct FailedRefresh {
    attempted_at: Instant,
    message: String,
}

#[derive(Default)]
struct PriceCacheState {
    cached: Option<CachedPriceQuote>,
    failed_refresh: Option<FailedRefresh>,
}

#[derive(Default)]
struct PriceCache {
    state: tokio::sync::Mutex<PriceCacheState>,
}

impl PriceCache {
    async fn get_or_refresh<F, Fut>(&self, refresh: F) -> WalletResult<SpotPrices>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<PriceQuote, RefreshError>>,
    {
        self.get_or_refresh_with(Instant::now, refresh).await
    }

    async fn get_or_refresh_with<N, F, Fut>(&self, now: N, refresh: F) -> WalletResult<SpotPrices>
    where
        N: Fn() -> Instant,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<PriceQuote, RefreshError>>,
    {
        // The guard stays held while refreshing. A successful miss is single-flight,
        // and a failed miss records a cooldown before queued callers continue.
        let mut state = self.state.lock().await;
        let evaluated_at = now();
        if let Some(cached) = state
            .cached
            .as_ref()
            .filter(|entry| is_recent(entry.stored_at, evaluated_at, FRESH_TTL))
        {
            return Ok(snapshot(cached, false));
        }

        if let Some(failed) = state
            .failed_refresh
            .as_ref()
            .filter(|failure| is_recent(failure.attempted_at, evaluated_at, FAILURE_RETRY_DELAY))
        {
            if let Some(cached) = usable_stale(&state, evaluated_at) {
                return Ok(snapshot(cached, true));
            }
            return Err(WalletError::Price(failed.message.clone()));
        }

        match refresh().await {
            Ok(quote) => {
                let cached = CachedPriceQuote {
                    quote,
                    observed_at_utc: chrono::Utc::now().to_rfc3339(),
                    stored_at: now(),
                };
                let result = snapshot(&cached, false);
                state.cached = Some(cached);
                state.failed_refresh = None;
                Ok(result)
            }
            Err((primary, fallback)) => {
                let message = format!(
                    "USD prices unavailable. CoinPaprika: {primary}; CoinGecko: {fallback}"
                );
                let failed_at = now();
                state.failed_refresh = Some(FailedRefresh {
                    attempted_at: failed_at,
                    message: message.clone(),
                });
                if let Some(cached) = usable_stale(&state, failed_at) {
                    return Ok(snapshot(cached, true));
                }
                Err(WalletError::Price(message))
            }
        }
    }
}

fn price_cache() -> &'static PriceCache {
    static CACHE: OnceLock<PriceCache> = OnceLock::new();
    CACHE.get_or_init(PriceCache::default)
}

/// Fetch a typed native price snapshot with bounded staleness and a
/// single-flight failure cooldown.
pub async fn fetch_spot_prices() -> WalletResult<SpotPrices> {
    let client = shared_http_client().map_err(WalletError::Price)?;
    price_cache()
        .get_or_refresh(|| refresh_prices(client))
        .await
}

async fn refresh_prices(client: &reqwest::Client) -> Result<PriceQuote, RefreshError> {
    tokio::time::timeout(TOTAL_REFRESH_TIMEOUT, async {
        match fetch_coinpaprika(client).await {
            Ok(quote) => Ok(quote),
            Err(primary_error) => fetch_coingecko(client)
                .await
                .map_err(|fallback_error| (primary_error, fallback_error)),
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err((
            "total refresh deadline exceeded".into(),
            "fallback did not complete before deadline".into(),
        ))
    })
}

fn is_recent(then: Instant, now: Instant, max_age: Duration) -> bool {
    now.saturating_duration_since(then) <= max_age
}

fn usable_stale(state: &PriceCacheState, now: Instant) -> Option<&CachedPriceQuote> {
    state
        .cached
        .as_ref()
        .filter(|entry| is_recent(entry.stored_at, now, MAX_STALE_AGE))
}
fn snapshot(cached: &CachedPriceQuote, stale: bool) -> SpotPrices {
    SpotPrices {
        hac_usd: cached.quote.hac_usd,
        hacd_usd: cached.quote.hacd_usd,
        btc_usd: cached.quote.btc_usd,
        source: cached.quote.source,
        stale,
        observed_at_utc: cached.observed_at_utc.clone(),
    }
}

async fn fetch_coinpaprika(client: &reqwest::Client) -> Result<PriceQuote, String> {
    let (hac, hacd, btc) = tokio::join!(
        fetch_coinpaprika_usd(client, "hac-hacash"),
        fetch_coinpaprika_usd(client, "hacd-hacash-diamond"),
        fetch_coinpaprika_usd(client, "btc-bitcoin"),
    );
    Ok(PriceQuote {
        hac_usd: hac?,
        hacd_usd: hacd?,
        btc_usd: btc?,
        source: PriceSource::CoinPaprika,
    })
}

async fn fetch_coinpaprika_usd(client: &reqwest::Client, id: &str) -> Result<f64, String> {
    let url = format!("https://api.coinpaprika.com/v1/tickers/{id}");
    let response = client
        .get(url)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await
        .map_err(|error| format!("{id}: {error}"))?;
    let data = read_json_bounded(response, id).await?;
    parse_coinpaprika_usd(&data).ok_or_else(|| format!("{id}: USD price missing or invalid"))
}

async fn fetch_coingecko(client: &reqwest::Client) -> Result<PriceQuote, String> {
    const URL: &str = "https://api.coingecko.com/api/v3/simple/price?ids=hacash,hacash-diamond,bitcoin&vs_currencies=usd";
    let mut last_error = String::from("no attempt");

    for attempt in 0..2 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
        let response = match client.get(URL).timeout(REQUEST_TIMEOUT).send().await {
            Ok(response) => response,
            Err(error) => {
                last_error = error.to_string();
                continue;
            }
        };
        let status = response.status();
        if retryable_provider_status(status) {
            last_error = format!("HTTP {status}");
            continue;
        }
        let data = read_json_bounded(response, "coingecko").await?;
        return parse_coingecko_prices(&data)
            .ok_or_else(|| "one or more USD prices are missing or invalid".to_string());
    }
    Err(last_error)
}

fn retryable_provider_status(status: reqwest::StatusCode) -> bool {
    status.as_u16() == 429 || status.is_server_error()
}
async fn read_json_bounded(
    mut response: reqwest::Response,
    label: &str,
) -> Result<serde_json::Value, String> {
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{label}: HTTP {status}"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(format!("{label}: response is too large"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("{label}: response read failed: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(format!("{label}: response is too large"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|error| format!("{label}: invalid response: {error}"))
}

fn positive_price(value: Option<f64>) -> Option<f64> {
    value.filter(|price| price.is_finite() && *price > 0.0)
}

fn parse_coinpaprika_usd(data: &serde_json::Value) -> Option<f64> {
    positive_price(data.get("quotes")?.get("USD")?.get("price")?.as_f64())
}

fn parse_coingecko_prices(data: &serde_json::Value) -> Option<PriceQuote> {
    let price = |id: &str| positive_price(data.get(id)?.get("usd")?.as_f64());
    Some(PriceQuote {
        hac_usd: price("hacash")?,
        hacd_usd: price("hacash-diamond")?,
        btc_usd: price("bitcoin")?,
        source: PriceSource::CoinGecko,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn quote(source: PriceSource) -> PriceQuote {
        PriceQuote {
            hac_usd: 1.0,
            hacd_usd: 2.0,
            btc_usd: 3.0,
            source,
        }
    }

    fn cached(stored_at: Instant) -> CachedPriceQuote {
        CachedPriceQuote {
            quote: quote(PriceSource::CoinPaprika),
            observed_at_utc: "2026-07-18T00:00:00Z".into(),
            stored_at,
        }
    }

    #[test]
    fn parses_all_coingecko_assets() {
        let data = serde_json::json!({
            "hacash": {"usd": 0.25},
            "hacash-diamond": {"usd": 51.5},
            "bitcoin": {"usd": 64000.0}
        });
        let quote = parse_coingecko_prices(&data).expect("valid quote");
        assert_eq!(quote.hac_usd, 0.25);
        assert_eq!(quote.hacd_usd, 51.5);
        assert_eq!(quote.btc_usd, 64000.0);
    }

    #[test]
    fn rejects_incomplete_non_positive_and_non_finite_prices() {
        for value in [
            serde_json::json!(0.0),
            serde_json::json!(-1.0),
            serde_json::json!(null),
        ] {
            let data = serde_json::json!({"quotes": {"USD": {"price": value}}});
            assert_eq!(parse_coinpaprika_usd(&data), None);
        }
        let missing_hacd = serde_json::json!({
            "hacash": {"usd": 0.25},
            "bitcoin": {"usd": 64000.0}
        });
        assert!(parse_coingecko_prices(&missing_hacd).is_none());
        assert_eq!(positive_price(Some(f64::INFINITY)), None);
        assert_eq!(positive_price(Some(f64::NAN)), None);
    }

    #[test]
    fn serializes_the_exact_native_ui_contract() {
        let value = serde_json::to_value(SpotPrices {
            hac_usd: 1.0,
            hacd_usd: 2.0,
            btc_usd: 3.0,
            source: PriceSource::CoinGecko,
            stale: true,
            observed_at_utc: "2026-07-18T00:00:00Z".into(),
        })
        .expect("serialize prices");
        assert_eq!(
            value,
            serde_json::json!({
                "hac_usd": 1.0,
                "hacd_usd": 2.0,
                "btc_usd": 3.0,
                "source": "coingecko",
                "stale": true,
                "observed_at_utc": "2026-07-18T00:00:00Z"
            })
        );
    }

    #[test]
    fn only_rate_limits_and_server_errors_are_retried() {
        assert!(retryable_provider_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(retryable_provider_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(!retryable_provider_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!retryable_provider_status(reqwest::StatusCode::NOT_FOUND));
    }

    #[tokio::test]
    async fn fresh_cache_does_not_start_a_refresh() {
        let origin = Instant::now();
        let evaluated_at = origin + Duration::from_secs(1);
        let cache = PriceCache {
            state: tokio::sync::Mutex::new(PriceCacheState {
                cached: Some(cached(origin)),
                failed_refresh: None,
            }),
        };
        let calls = AtomicUsize::new(0);
        let result = cache
            .get_or_refresh_with(
                || evaluated_at,
                || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(quote(PriceSource::CoinGecko))
                },
            )
            .await
            .expect("cached quote");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!result.stale);
        assert_eq!(result.source, PriceSource::CoinPaprika);
    }

    #[tokio::test]
    async fn successful_refresh_replaces_expired_quote() {
        let origin = Instant::now();
        let evaluated_at = origin + FRESH_TTL + Duration::from_secs(1);
        let cache = PriceCache {
            state: tokio::sync::Mutex::new(PriceCacheState {
                cached: Some(cached(origin)),
                failed_refresh: None,
            }),
        };
        let result = cache
            .get_or_refresh_with(
                || evaluated_at,
                || async { Ok(quote(PriceSource::CoinGecko)) },
            )
            .await
            .expect("refreshed quote");
        assert!(!result.stale);
        assert_eq!(result.source, PriceSource::CoinGecko);
        assert_ne!(result.observed_at_utc, "2026-07-18T00:00:00Z");
    }

    #[tokio::test]
    async fn concurrent_failed_refreshes_share_one_attempt_and_stale_snapshot() {
        let origin = Instant::now();
        let evaluated_at = origin + FRESH_TTL + Duration::from_secs(1);
        let cache = Arc::new(PriceCache {
            state: tokio::sync::Mutex::new(PriceCacheState {
                cached: Some(cached(origin)),
                failed_refresh: None,
            }),
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            let calls = Arc::clone(&calls);
            tasks.push(tokio::spawn(async move {
                cache
                    .get_or_refresh_with(
                        || evaluated_at,
                        move || async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            Err(("primary offline".into(), "fallback offline".into()))
                        },
                    )
                    .await
            }));
        }
        for task in tasks {
            let result = task.await.expect("task joined").expect("stale quote");
            assert!(result.stale);
            assert_eq!(result.observed_at_utc, "2026-07-18T00:00:00Z");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cold_failure_is_reused_during_the_retry_cooldown() {
        let cache = PriceCache::default();
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            let error = cache
                .get_or_refresh(|| async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(("primary offline".into(), "fallback offline".into()))
                })
                .await
                .expect_err("cold cache must fail");
            assert!(error.to_string().contains("primary offline"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn overage_cache_is_not_returned_after_provider_failure() {
        let origin = Instant::now();
        let evaluated_at = origin + MAX_STALE_AGE + Duration::from_secs(1);
        let cache = PriceCache {
            state: tokio::sync::Mutex::new(PriceCacheState {
                cached: Some(cached(origin)),
                failed_refresh: None,
            }),
        };
        let error = cache
            .get_or_refresh_with(
                || evaluated_at,
                || async { Err(("primary offline".into(), "fallback offline".into())) },
            )
            .await
            .expect_err("overage quote");
        assert!(error.to_string().contains("USD prices unavailable"));
    }
    #[tokio::test]
    async fn bounded_reader_rejects_an_oversized_body() {
        use axum::Router;
        use axum::routing::get;

        let app = Router::new().route(
            "/oversized",
            get(|| async { "x".repeat(MAX_RESPONSE_BYTES + 1) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind price test server");
        let address = listener.local_addr().expect("price test address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve price test");
        });
        let response = shared_http_client()
            .expect("shared HTTP client")
            .get(format!("http://{address}/oversized"))
            .send()
            .await
            .expect("oversized response");
        let error = read_json_bounded(response, "oversized")
            .await
            .expect_err("oversized body");
        assert!(error.contains("too large"));
        server.abort();
    }
}
