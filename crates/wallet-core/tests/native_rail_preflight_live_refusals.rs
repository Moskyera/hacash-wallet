//! Break ONE thing at a time, against the live chain 7 pilot node and live
//! Hubs started from this tree, and show the refusal each time.
//!
//! The sibling `native_rail_preflight_live_readonly.rs` shows the preflight
//! answering honestly about the node. This file shows it answering honestly
//! about the Hub and about the owner's own inputs, one broken thing per
//! scenario, so that each refusal can be read on its own.
//!
//! NOTHING HERE MOVES VALUE, AND NOTHING HERE CAN. Every scenario calls
//! `observe` (five GETs) and `judge` (pure). No transaction is built, signed or
//! submitted, no wallet is unlocked, no Hub is asked to open, settle or close
//! anything, and no request ever leaves 127.0.0.1 except the one scenario whose
//! whole point is that the URL is refused before a socket is opened.
//!
//! `#[ignore]`, so `cargo test` and CI are unaffected.
//!
//! Environment: `HPAY_PREFLIGHT_NODE_URL` (default `http://127.0.0.1:8197`),
//! `HPAY_PREFLIGHT_SEED` (default a fixed local string; derives identities
//! only, and no key here ever signs).

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::hpay_native_rail_preflight::{
    CheckSeverity, CheckStatus, PreflightReport, PreflightRequest, PreflightVerdict, judge, observe,
};
use l2_fast_pay_hub::readiness::MainnetPilotAdmissionPolicy;
use l2_fast_pay_hub::{HubState, build_router};

const ZHU_PER_HAC: u64 = 100_000_000;
const MAX_PAYMENT_ZHU: u64 = ZHU_PER_HAC;
const MAX_CHANNEL_ZHU: u64 = 10 * ZHU_PER_HAC;
const MAX_AGGREGATE_TVL_ZHU: u64 = 100 * ZHU_PER_HAC;

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn seed() -> String {
    env_or("HPAY_PREFLIGHT_SEED", "hpay-native-rail-preflight-local")
}

fn node_url() -> String {
    env_or("HPAY_PREFLIGHT_NODE_URL", "http://127.0.0.1:8197")
}

fn derived_key_hex(label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed().as_bytes());
    hasher.update(b"::");
    hasher.update(label.as_bytes());
    hex::encode(hasher.finalize())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn workdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("hpay-preflight-refusals")
        .join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Start the real Hub, in this process, on a real socket, with the same
/// `HubState` and `build_router` that `fast-pay-hub.exe` serves. Started, not
/// driven: it answers GETs and is never asked to open or settle anything.
///
/// `max_channel_zhu` is a parameter because one scenario needs a Hub that
/// declares a cap below the deposit, and the honest way to get one is to start
/// a real Hub configured that way, not to edit a response.
async fn start_real_hub(name: &str, owner: &str, max_channel_zhu: u64) -> (String, String) {
    let account = WalletAccount::create(&format!("{}::hub::{name}", seed())).unwrap();
    let address = account.address();
    let admission = MainnetPilotAdmissionPolicy::try_new([owner], MAX_AGGREGATE_TVL_ZHU).unwrap();
    let state = Arc::new(
        HubState::new_secure_with_mainnet_admission(
            format!("HPAY native-rail refusal Hub ({name})"),
            address.clone(),
            node_url(),
            None,
            workdir(name).join("hub.sealed.json"),
            account.secret_hex().to_string(),
            &derived_key_hex("journal"),
            &derived_key_hex("state"),
            "mainnet-bounded-pilot".to_owned(),
            MAX_PAYMENT_ZHU,
            max_channel_zhu,
            admission,
        )
        .expect("hub state"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });
    (url, address)
}

/// A stand-in for a Hub build that predates the close-voucher work.
///
/// It is NOT a hand-written fixture: every byte it serves on `/v1/health` and
/// `/v1/readiness/mainnet` is fetched live from the real Hub above at the
/// moment of the request. Exactly two things differ, and they are the two
/// things that were actually different about an older build: `version` reads 6
/// instead of 7, and there is no `/v1/l1/channel/close-voucher` route at all,
/// so axum answers that path 404. That is what an older Hub looks like on the
/// wire, and it is the only way to show this refusal without checking out an
/// older tree.
async fn start_pre_voucher_hub_shim(upstream: String) -> String {
    async fn health(State(upstream): State<String>) -> axum::Json<serde_json::Value> {
        let mut body: serde_json::Value = reqwest::get(format!("{upstream}/v1/health"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        body["version"] = serde_json::json!(6);
        axum::Json(body)
    }
    async fn readiness(State(upstream): State<String>) -> axum::Json<serde_json::Value> {
        let body: serde_json::Value = reqwest::get(format!("{upstream}/v1/readiness/mainnet"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        axum::Json(body)
    }
    let router = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/readiness/mainnet", get(readiness))
        .with_state(upstream);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    url
}

/// A port with nothing behind it. Bind it, learn the number, drop the listener.
async fn a_port_with_nothing_listening() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

fn mark(check: &hacash_wallet_core::hpay_native_rail_preflight::PreflightCheck) -> &'static str {
    match (check.severity, check.status) {
        (_, CheckStatus::Pass) => "PASS",
        (CheckSeverity::Fatal, CheckStatus::Fail) => "FATAL FAIL",
        (CheckSeverity::Fatal, CheckStatus::Skip) => "FATAL, NOT CHECKED",
        (CheckSeverity::Warning, CheckStatus::Fail) => "warn",
        (CheckSeverity::Warning, CheckStatus::Skip) => "warn skip",
    }
}

/// Run one scenario, print the whole report, and enforce the one rule that
/// must hold in every scenario: no overall pass while any fatal item failed or
/// was skipped.
async fn run_scenario(label: &str, broke: &str, request: &PreflightRequest) -> PreflightReport {
    println!("\n\n================================================================");
    println!("SCENARIO: {label}");
    println!("BROKEN:   {broke}");
    println!("node: {}", request.node_url);
    println!("hub:  {}", request.hub_url);
    println!("================================================================");

    let report = judge(request, &observe(request).await);

    for check in &report.checks {
        println!("[{}] {} ({})", mark(check), check.title, check.id);
        println!("    observed: {}", check.observed);
        if let Some(reason) = &check.reason {
            println!("    note:     {reason}");
        }
    }
    println!(
        "\n[VERDICT] {:?}   fatal failed {}   fatal skipped {}   warnings {}",
        report.verdict, report.fatal_failed, report.fatal_skipped, report.warnings
    );

    // The invariant, re-checked live in every scenario, from the items rather
    // than from the verdict field.
    let fatal_not_pass = report
        .checks
        .iter()
        .filter(|check| check.severity == CheckSeverity::Fatal)
        .filter(|check| check.status != CheckStatus::Pass)
        .count();
    if fatal_not_pass > 0 {
        assert_eq!(
            report.verdict,
            PreflightVerdict::NotPass,
            "{label}: {fatal_not_pass} fatal item(s) did not pass, so the verdict must not be Pass"
        );
    }
    assert_eq!(
        report.fatal_failed + report.fatal_skipped,
        fatal_not_pass,
        "{label}: the counters must agree with the items"
    );
    report
}

fn find<'a>(
    report: &'a PreflightReport,
    id: &str,
) -> &'a hacash_wallet_core::hpay_native_rail_preflight::PreflightCheck {
    report
        .checks
        .iter()
        .find(|check| check.id == id)
        .unwrap_or_else(|| panic!("no check with id {id}"))
}

fn base_request(
    node_url: String,
    hub_url: String,
    hub_address: String,
    owner: String,
) -> PreflightRequest {
    PreflightRequest {
        node_url,
        hub_url,
        hub_address,
        owner_address: owner,
        channel_deposit_hac: "1".to_owned(),
        payment_hac: "0.1".to_owned(),
    }
}

#[test]
#[ignore = "live read-only observation only"]
fn each_broken_thing_gets_its_own_refusal() {
    runtime().block_on(async {
        let owner = WalletAccount::create(&format!("{}::owner", seed()))
            .unwrap()
            .address();
        let node = node_url();

        // ---- the control: a real Hub, correct inputs -------------------
        let (good_hub_url, good_hub_address) =
            start_real_hub("control", &owner, MAX_CHANNEL_ZHU).await;
        let control = run_scenario(
            "CONTROL: real chain 7 node, real Hub from this tree, correct inputs",
            "nothing. This is the baseline the five refusals below are measured against",
            &base_request(
                node.clone(),
                good_hub_url.clone(),
                good_hub_address.clone(),
                owner.clone(),
            ),
        )
        .await;
        // Chain 7 is not mainnet, so even the control must refuse.
        assert_eq!(control.verdict, PreflightVerdict::NotPass);
        assert_eq!(find(&control, "node_identity").status, CheckStatus::Fail);
        // ... but everything that is genuinely fine here is green.
        for green in [
            "voucher_parties",
            "voucher_route",
            "declared_caps",
            "hub_open_ready",
        ] {
            assert_eq!(
                find(&control, green).status,
                CheckStatus::Pass,
                "{green} should be green in the control"
            );
        }

        // ---- 1. a Hub that is not running ------------------------------
        let dead = a_port_with_nothing_listening().await;
        let report = run_scenario(
            "1. A HUB THAT IS NOT RUNNING",
            "the Hub URL points at a port with nothing behind it",
            &base_request(node.clone(), dead, good_hub_address.clone(), owner.clone()),
        )
        .await;
        for id in [
            "hub_open_ready",
            "hub_voucher_ready",
            "voucher_route",
            "readiness_document",
            "declared_caps",
            "hub_fullnode",
            "hub_blockers",
        ] {
            assert_eq!(
                find(&report, id).status,
                CheckStatus::Skip,
                "{id} must be SKIP, not PASS, when the Hub never answered"
            );
        }
        assert!(report.fatal_skipped >= 7);
        assert_eq!(report.verdict, PreflightVerdict::NotPass);

        // ---- 2. a declared cap below the intended deposit ---------------
        let (small_hub_url, small_hub_address) =
            start_real_hub("small-cap", &owner, ZHU_PER_HAC / 2).await;
        let report = run_scenario(
            "2. A HUB WHOSE DECLARED CAP IS BELOW THE INTENDED DEPOSIT",
            "a real Hub started with a per-channel cap of 0.5 HAC, against a 1 HAC deposit",
            &base_request(
                node.clone(),
                small_hub_url,
                small_hub_address,
                owner.clone(),
            ),
        )
        .await;
        let caps = find(&report, "declared_caps");
        assert_eq!(caps.status, CheckStatus::Fail);
        assert!(
            caps.reason
                .as_deref()
                .unwrap_or_default()
                .contains("per-channel cap"),
            "the refusal must name the cap it broke: {:?}",
            caps.reason
        );

        // ---- 3. a plaintext remote node URL -----------------------------
        // Refused by the transport predicate before any socket is opened, so
        // nothing is sent to this address.
        let report = run_scenario(
            "3. A PLAINTEXT REMOTE NODE URL",
            "node URL is plain http against a non-loopback host",
            &base_request(
                "http://203.0.113.10:8197".to_owned(),
                good_hub_url.clone(),
                good_hub_address.clone(),
                owner.clone(),
            ),
        )
        .await;
        assert_eq!(find(&report, "signing_transport").status, CheckStatus::Fail);
        for id in [
            "node_identity",
            "block_one",
            "tip_freshness",
            "node_action_set",
            "node_api_surface",
        ] {
            assert_eq!(
                find(&report, id).status,
                CheckStatus::Skip,
                "{id} must be SKIP when the node was never contacted"
            );
        }

        // ---- 4. an address the Hub will not act for ----------------------
        let stranger = WalletAccount::create(&format!("{}::stranger", seed()))
            .unwrap()
            .address();
        assert_ne!(stranger, good_hub_address);
        let report = run_scenario(
            "4. AN ADDRESS THE HUB WILL NOT ACT FOR",
            "the wallet expects a Hub address this running Hub does not publish",
            &base_request(
                node.clone(),
                good_hub_url.clone(),
                stranger.clone(),
                owner.clone(),
            ),
        )
        .await;
        for id in ["hub_open_ready", "hub_voucher_ready"] {
            let check = find(&report, id);
            assert_eq!(check.status, CheckStatus::Fail, "{id} must refuse");
            assert!(
                check
                    .reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains(&stranger),
                "{id} must name the address the wallet expected: {:?}",
                check.reason
            );
        }

        // ---- 5. a Hub too old to issue a voucher -------------------------
        let old = start_pre_voucher_hub_shim(good_hub_url.clone()).await;
        let report = run_scenario(
            "5. A HUB TOO OLD TO ISSUE A VOUCHER",
            "API version 6 and no /v1/l1/channel/close-voucher route, both served over real HTTP",
            &base_request(node.clone(), old, good_hub_address.clone(), owner.clone()),
        )
        .await;
        let route = find(&report, "voucher_route");
        assert_eq!(route.status, CheckStatus::Fail);
        assert!(
            route.observed.contains("404"),
            "observed: {}",
            route.observed
        );
        assert!(
            route
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Do not fund it"),
            "the refusal must say not to fund: {:?}",
            route.reason
        );
        for id in ["hub_open_ready", "hub_voucher_ready"] {
            let check = find(&report, id);
            assert_eq!(
                check.status,
                CheckStatus::Fail,
                "{id} must refuse an older Hub"
            );
            assert!(
                check
                    .reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("API version 6"),
                "{id} must name the version: {:?}",
                check.reason
            );
        }

        println!("\n\n=== every scenario refused, and no scenario printed a pass ===");
    });
}
