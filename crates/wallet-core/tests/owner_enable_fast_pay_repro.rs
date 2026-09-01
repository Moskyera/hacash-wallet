//! THE OWNER'S EXACT CONFIGURATION, PRESSING "ENABLE FAST PAY".
//!
//! The owner reported that "Enable Fast Pay" does not start. Every backend gate
//! had been read by hand and judged passing against their live Hub: schema
//! matches, `payments_enabled` true, `mainnet_detected` true, profile
//! `mainnet-bounded-pilot` with `trusted_bounded_pilot` true, `blockers` empty,
//! caps 0.1 / 0.2 HAC inside the hard ceilings, balance 6.79 HAC.
//!
//! This file stops the reading and measures it. A stub Hub serves exactly those
//! documents on a real loopback socket, a real `WalletService` is pointed at it
//! in mainnet mode with consent granted and no channel, and the functions the
//! two buttons reach are called for real.
//!
//! NO MAINNET CONTACT AND NO VALUE MOVES. The Hub here is 40 lines of axum
//! serving two JSON documents; the fullnode URL is a dead loopback port that is
//! never listening. Nothing signs, nothing broadcasts,
//! `execute_prepared_channel_open` is never called, and every call made here
//! either reads a document or judges one already in hand.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::{Router, routing::get};
use hacash_wallet_core::WalletService;
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::l2_hub::L2HubClient;

const VAULT_PASSPHRASE: &str = "owner-enable-fast-pay-repro-passphrase";

/// The owner's Hub caps, verbatim, in zhu. 1 HAC = 100_000_000 zhu, so these
/// are 0.1 HAC per payment and 0.2 HAC per channel.
const OWNER_MAX_PAYMENT_ZHU: u64 = 10_000_000;
const OWNER_MAX_CHANNEL_FUNDING_ZHU: u64 = 20_000_000;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A Hub whose readiness clock this test can move.
///
/// `age_seconds` is added to "now" when the document is composed, so a value of
/// `-90` serves a document that was evaluated ninety seconds ago and expired
/// thirty seconds ago. That is the exact shape of the sixty-second window
/// closing between the moment a screen renders and the moment a human clicks.
struct StubHub {
    url: String,
    address: String,
    age_seconds: Arc<AtomicI64>,
    task: tokio::task::JoinHandle<()>,
}

fn health_json(hub_address: &str) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "version": 7,
        "name": "Owner local Hub",
        "hub_address": hub_address,
        "hub_fee_mei": "0",
        "settlement_ready": true,
        "cross_channel_ready": true,
        "deployment_profile": "mainnet-bounded-pilot"
    })
}

/// The owner's readiness document. Every gating field set to the value the
/// owner verified by hand against their live Hub.
fn readiness_json(age_seconds: i64) -> serde_json::Value {
    let evaluated = (unix_now() as i64 + age_seconds) as u64;
    serde_json::json!({
        "schema": "hpay-fast-pay-mainnet-readiness/1",
        "evaluated_unix": evaluated,
        // Sixty seconds. This is the owner's live number: evaluated_unix
        // 1787663426, valid_until_unix 1787663486.
        "valid_until_unix": evaluated + 60,
        "profile": "mainnet-bounded-pilot",
        "payments_enabled": true,
        "close_enabled": true,
        "mainnet_detected": true,
        "trusted_bounded_pilot": true,
        "fullnode_capabilities": {
            "observed_unix": evaluated,
            "api_version": 1,
            "chain_id": 0,
            "height": 900_000,
            "next_height": 900_001,
            "mainnet": true,
            "network_instance_id": "55".repeat(32),
            "tip_timestamp_unix": evaluated,
            "tip_age_seconds": 0,
            // 2 is channel open, 3 is cooperative close. Both required.
            "enabled_actions": [1, 2, 3]
        },
        "max_payment_hac_zhu": OWNER_MAX_PAYMENT_ZHU,
        "max_channel_funding_hac_zhu": OWNER_MAX_CHANNEL_FUNDING_ZHU,
        "max_aggregate_tvl_hac_zhu": 10_000_000_000_u64,
        "aggregate_tvl_within_limit": true,
        "max_payment_satoshi": 0,
        "wallet_fee_hac": "0",
        "trustless_finality": false,
        "unilateral_l1_enforceable": false,
        "settlement_model": "official Hacash ChannelPay bills with hub-coordinated bounded mainnet pilot",
        "blockers": [],
        "close_blockers": [],
        "disclosed_blockers": [
            "external_monotonic_rollback_anchor_is_not_ready",
            "unilateral_l1_dispute_path_is_not_ready"
        ],
        "limitations": ["settled does not mean unilateral L1 finality"]
    })
}

async fn start_stub_hub() -> StubHub {
    let address = WalletAccount::create("owner-repro::hub").unwrap().address();
    let age = Arc::new(AtomicI64::new(0));
    let served_address = address.clone();
    let served_age = age.clone();
    let router = Router::new()
        .route(
            "/v1/health",
            get(move || {
                let address = served_address.clone();
                async move { axum::Json(health_json(&address)) }
            }),
        )
        .route(
            "/v1/readiness/mainnet",
            get(move || {
                let age = served_age.clone();
                async move { axum::Json(readiness_json(age.load(Ordering::SeqCst))) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    StubHub {
        url,
        address,
        age_seconds: age,
        task,
    }
}

/// The owner's wallet: mainnet, their Hub, consent granted, no channel.
fn owner_wallet(work: &std::path::Path, hub: &StubHub, node_url: &str) -> WalletService {
    let payer = WalletAccount::create("owner-repro::payer").unwrap();
    let payer_address = payer.address();
    std::fs::create_dir_all(work).unwrap();
    // SAFETY: single-threaded setup before any wallet thread exists.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work);
        std::env::set_var("HACASH_WALLET_NETWORK", "mainnet");
    }
    let mut wallet = WalletService::new(Some(node_url.to_owned()), Some(hub.url.clone())).unwrap();
    if wallet.unlock(VAULT_PASSPHRASE).is_err() {
        wallet
            .import_wallet(&payer.secret_hex(), VAULT_PASSPHRASE, &payer_address)
            .expect("import");
    }
    let mut settings = wallet.get_settings();
    settings.node_url = node_url.to_owned();
    settings.network_mode = "mainnet".into();
    settings.l2_hub_url = Some(hub.url.clone());
    settings.hub_right_address = Some(hub.address.clone());
    settings.channel_id_hex = None;
    wallet.update_settings(settings).expect("settings");
    wallet
        .set_trusted_mainnet_fast_pay_pilot(VAULT_PASSPHRASE, true)
        .expect("authenticated bounded pilot consent");
    wallet
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The owner's configuration, and `enable_fast_pay` called exactly as
/// `api.enableFastPay` would call it.
#[test]
fn owner_configuration_enable_fast_pay_reaches_needs_channel() {
    runtime().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let hub = start_stub_hub().await;
        // A dead loopback port. Never listening, so nothing can be broadcast.
        let node_url = "http://127.0.0.1:19999".to_owned();
        let mut wallet = owner_wallet(dir.path(), &hub, &node_url);

        // The gates the owner read, judged for real against the served document.
        let client = L2HubClient::new_for_wallet_policy(hub.url.clone(), "mainnet", true);
        let readiness = client
            .require_mainnet_payment_ready(None)
            .await
            .expect("the owner's readiness document must pass the payment gate");
        println!(
            "[gate] require_mainnet_payment_ready -> OK, max_channel_funding {} zhu ({} millimeis)",
            readiness.max_channel_funding_hac_zhu,
            OWNER_MAX_CHANNEL_FUNDING_ZHU / 100_000
        );

        let result = wallet.enable_fast_pay(None).await;
        match &result {
            Ok(status) => println!(
                "[user] enable_fast_pay(None) -> state {:?} can_enable {} deposit {} message {:?}",
                status.state, status.can_enable, status.default_deposit_mei, status.message
            ),
            Err(error) => println!("[user] enable_fast_pay(None) -> REFUSED: {error}"),
        }
        let status = result.expect("enable_fast_pay must reach needs_channel, not refuse");
        assert!(status.can_enable);
        assert_eq!(
            status.default_deposit_mei, 0.2,
            "the deposit must be the Hub's own channel cap, 0.2 HAC"
        );

        hub.task.abort();
    });
}

/// The field both apps read to decide whether Fast Pay is ON.
///
/// `WalletStatus::fast_pay_state` is produced by `fast_pay_status_sync`, which
/// is a two-line function: a Hub URL is configured, so `checking`; otherwise
/// `no_provider`. It cannot return `ready` and it cannot return `needs_channel`
/// under any configuration, because it never asks the Hub or the node anything.
///
/// Both apps test it for exactly those two values:
///
/// * desktop `App.tsx`: `fastPayReady = status.fast_pay_state === "ready"`,
///   `fastPayNeedsSetup = status.fast_pay_state === "needs_channel"`
/// * mobile `MobileApp.tsx`: `fastPayReady={status.fast_pay_state === "ready"}`
///
/// So the ON/OFF pill, the "when you tap Send" line, the nav badge and the
/// "Go to Send" box are all wired to a predicate that can never become true.
#[test]
fn wallet_status_never_reports_ready_or_needs_channel() {
    runtime().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let hub = start_stub_hub().await;
        let node_url = "http://127.0.0.1:19999".to_owned();
        let mut wallet = owner_wallet(dir.path(), &hub, &node_url);

        // The authoritative answer, the one `wallet_fast_pay_status` returns.
        let detail = wallet.fast_pay_status().await.expect("fast pay status");
        // The answer `wallet_status` returns, for the same wallet at the same
        // instant, out of the same settings.
        let status = wallet.status();

        println!(
            "[both] fast_pay_status().state = {:?}   status().fast_pay_state = {:?}",
            detail.state, status.fast_pay_state
        );
        assert_eq!(detail.state.as_str(), "needs_channel");
        assert_eq!(
            status.fast_pay_state, "checking",
            "the field the UI reads is a placeholder, not a state"
        );
        assert_ne!(status.fast_pay_state, "ready");
        assert_ne!(status.fast_pay_state, "needs_channel");

        hub.task.abort();
    });
}

/// The sixty-second window, closed.
///
/// A screen that fetches readiness, renders, and waits for a human is holding a
/// document that expires while they read it. This is what the person is told
/// when they finally click.
#[test]
fn an_expired_readiness_document_refuses_and_says_only_that_it_is_invalid() {
    runtime().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let hub = start_stub_hub().await;
        // Evaluated 90 seconds ago, so valid_until was 30 seconds ago.
        hub.age_seconds.store(-90, Ordering::SeqCst);
        let node_url = "http://127.0.0.1:19999".to_owned();
        let mut wallet = owner_wallet(dir.path(), &hub, &node_url);

        let error = wallet
            .enable_fast_pay(None)
            .await
            .expect_err("an expired readiness document must refuse");
        println!("[user] enable_fast_pay with an expired document -> {error}");
        assert!(
            error.to_string().contains("expired"),
            "the refusal must name expiry: {error}"
        );

        hub.task.abort();
    });
}

/// The URL IS set, the Hub IS fine, and something later fails.
///
/// `enable_fast_pay` opens with
/// `if self.settings.l2_hub_url.is_none() && let Some(discovered) = ...`, so the
/// discovery branch is skipped entirely for a configured wallet. The question
/// is what the next failure looks like. Here the Hub's channel cap is fine but
/// the caller asks for more than it: the refusal must name the cap.
#[test]
fn a_deposit_over_the_hubs_channel_cap_is_refused_by_name() {
    runtime().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let hub = start_stub_hub().await;
        let node_url = "http://127.0.0.1:19999".to_owned();
        let mut wallet = owner_wallet(dir.path(), &hub, &node_url);

        // The number the desktop screen's deposit field holds before
        // `fastPayDetail.default_deposit_mei` arrives: `useState("10")`.
        let error = wallet
            .enable_fast_pay(Some(10.0))
            .await
            .expect_err("10 HAC is fifty times this Hub's 0.2 HAC channel cap");
        println!("[user] enable_fast_pay(Some(10.0)) -> {error}");
        assert!(
            error.to_string().contains("20000000"),
            "the refusal must quote the Hub's own cap: {error}"
        );

        hub.task.abort();
    });
}
