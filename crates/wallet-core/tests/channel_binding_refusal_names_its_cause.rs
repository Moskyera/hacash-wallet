//! THE REFUSAL BEHIND "ENABLE FAST PAY", AND WHETHER IT NAMES ANYTHING.
//!
//! `require_channel_binding_ready` is the gate `prepare_channel_open` calls, so
//! it is the gate the "Enable Fast Pay" button actually hits. Its first check is
//! five conditions joined by `||`:
//!
//! ```ignore
//! if !health.ok
//!     || health.version < 7
//!     || !health.settlement_ready
//!     || !health.cross_channel_ready
//!     || !hub_fee_is_zero(&health)
//! ```
//!
//! and every one of them produced the same sentence: "Fast Pay provider is not
//! ready for safe, fee-free routed settlement". That names none of the five, and
//! it quotes nothing the Hub published.
//!
//! It matters most for the version, because the wallet and this gate disagree
//! about the minimum. Discovery, `evaluate_fast_pay` and `enable_fast_pay` all
//! accept `version >= 3` (fast_pay.rs:234, :456, :501, wallet.rs:1802). This
//! gate requires `>= 7`. A Hub publishing 3 through 6 is therefore shown as
//! online, sets the state to `needs_channel`, renders and un-greys the Enable
//! button, and is then refused at prepare with a sentence naming neither the
//! version it has nor the version it needs.
//!
//! THE GATE IS NOT WEAKENED HERE. Version 7 is still required and every one of
//! the five conditions still refuses. What these tests demand is that the
//! refusal say which one, and in the version's case say both numbers.
//!
//! NO MAINNET CONTACT AND NO VALUE MOVES. This is a stub Hub on a loopback
//! socket serving one JSON document, and one gate function judging it. Nothing
//! signs and nothing is broadcast.

use axum::{Router, routing::get};
use hacash_wallet_core::l2_hub::L2HubClient;

struct StubHub {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

/// A healthy, fee-free, settlement-ready Hub, with every field the gate reads
/// set to a passing value. Individual tests spoil exactly one.
fn health_json(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = serde_json::json!({
        "ok": true,
        "version": 7,
        "name": "Stub Hub",
        "hub_address": "1HubAddressPlaceholderForGateTest",
        "hub_fee_mei": "0",
        "settlement_ready": true,
        "cross_channel_ready": true,
        "trusted_bounded_pilot_ready": true,
        "deployment_profile": "mainnet-bounded-pilot"
    });
    let map = base.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        map.insert(key.clone(), value.clone());
    }
    base
}

async fn start_stub_hub(health: serde_json::Value) -> StubHub {
    let router = Router::new().route(
        "/v1/health",
        get(move || {
            let health = health.clone();
            async move { axum::Json(health) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    StubHub { url, task }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Run the gate a testnet wallet reaches, so the refusal under test is the
/// five-condition one and not a mainnet readiness refusal further down.
async fn refusal_for(health: serde_json::Value) -> String {
    let hub = start_stub_hub(health).await;
    let client = L2HubClient::new_for_wallet_policy(hub.url.clone(), "testnet", false);
    let result = client
        .require_channel_binding_ready("1HubAddressPlaceholderForGateTest", "0.2")
        .await;
    hub.task.abort();
    match result {
        Ok(_) => panic!("the gate was expected to refuse this Hub, and it accepted it"),
        Err(error) => {
            let text = error.to_string();
            println!("[refusal] {text}");
            text
        }
    }
}

#[test]
fn a_hub_below_the_required_version_is_told_both_numbers() {
    runtime().block_on(async {
        // 6 is the interesting case: discovery and `enable_fast_pay` accept it
        // at `>= 3`, so the button is offered, and this gate rejects it at `< 7`.
        let text = refusal_for(health_json(serde_json::json!({ "version": 6 }))).await;
        assert!(
            text.contains('6'),
            "the refusal must quote the version the provider actually publishes; got: {text}"
        );
        assert!(
            text.contains('7'),
            "the refusal must quote the version this wallet requires; got: {text}"
        );
        assert!(
            text.to_lowercase().contains("version"),
            "the refusal must say the word version, not leave a person to guess which \
             of five conditions failed; got: {text}"
        );
    });
}

#[test]
fn a_hub_that_charges_a_fee_is_told_the_fee_is_the_problem() {
    runtime().block_on(async {
        let text = refusal_for(health_json(serde_json::json!({ "hub_fee_mei": "0.001" }))).await;
        assert!(
            text.to_lowercase().contains("fee"),
            "the refusal must name the fee as the cause; got: {text}"
        );
        assert!(
            text.contains("0.001"),
            "the refusal must quote the fee the provider published; got: {text}"
        );
    });
}

#[test]
fn a_hub_that_cannot_settle_is_told_settlement_is_the_problem() {
    runtime().block_on(async {
        let text = refusal_for(health_json(
            serde_json::json!({ "settlement_ready": false }),
        ))
        .await;
        let lower = text.to_lowercase();
        // The literal field name, not the word "settlement", which the old
        // one-size-fits-all sentence already contained by accident.
        assert!(
            text.contains("settlement_ready"),
            "the refusal must name the published field that is false, so the person \
             can look it up in their own Hub's /v1/health; got: {text}"
        );
        assert!(
            !lower.contains("version"),
            "this Hub's version is fine; naming the version here would send a person \
             to fix something that is not broken; got: {text}"
        );
    });
}

#[test]
fn a_hub_without_routed_payments_is_told_routing_is_the_problem() {
    runtime().block_on(async {
        let text = refusal_for(health_json(
            serde_json::json!({ "cross_channel_ready": false }),
        ))
        .await;
        // Again the literal field name: "routed" alone is in the generic sentence.
        assert!(
            text.contains("cross_channel_ready"),
            "the refusal must name the published field that is false; got: {text}"
        );
    });
}

#[test]
fn a_hub_reporting_not_ok_is_told_so_in_its_own_terms() {
    runtime().block_on(async {
        let text = refusal_for(health_json(serde_json::json!({ "ok": false }))).await;
        let lower = text.to_lowercase();
        assert!(
            lower.contains("not healthy") || lower.contains("reports itself"),
            "the refusal must say the provider reported itself unhealthy; got: {text}"
        );
    });
}

#[test]
fn several_failures_at_once_are_all_named() {
    runtime().block_on(async {
        // A person fixing one cause at a time, pressing again, and getting a new
        // single-cause refusal each time is a bad afternoon. Name them all.
        let text = refusal_for(health_json(serde_json::json!({
            "version": 4,
            "settlement_ready": false,
            "hub_fee_mei": "0.5"
        })))
        .await;
        let lower = text.to_lowercase();
        assert!(lower.contains("version"), "version not named; got: {text}");
        assert!(
            lower.contains("settle"),
            "settlement not named; got: {text}"
        );
        assert!(lower.contains("fee"), "fee not named; got: {text}");
    });
}

#[test]
fn the_refusal_still_refuses() {
    runtime().block_on(async {
        // The point of this change is the wording, not the verdict. A version 6
        // Hub must still be refused, because the channel-binding guarantees this
        // wallet depends on are not there below 7.
        let hub = start_stub_hub(health_json(serde_json::json!({ "version": 6 }))).await;
        let client = L2HubClient::new_for_wallet_policy(hub.url.clone(), "testnet", false);
        let result = client
            .require_channel_binding_ready("1HubAddressPlaceholderForGateTest", "0.2")
            .await;
        hub.task.abort();
        assert!(
            result.is_err(),
            "version 6 must still be refused; this test exists so that a future edit \
             cannot turn a naming fix into a weakened gate"
        );
    });
}
