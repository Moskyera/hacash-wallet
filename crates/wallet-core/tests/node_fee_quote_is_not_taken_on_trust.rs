//! A FEE THE NODE INVENTED MUST NOT ARRIVE WEARING THE WALLET'S ENDORSEMENT.
//!
//! The sibling file `l1_fee_fallback_is_audible.rs` covers the case where the
//! node says nothing and the wallet makes a number up. This is the other
//! direction, and it is the one an attacker uses: the node answers, promptly
//! and in the right shape, with a number that is a thousand times the truth.
//!
//! Measured on the proposed official-node path before this guard existed:
//! `/query/fee/average` returning `feasible: 1.0` instead of `0.001` produced a
//! review screen reading `Amount = 1 HAC`, `Network fee = 1.2` and, beneath
//! them, `Fee estimate = Quoted by the node`. The transaction was signed and
//! broadcast. The number was on the screen the whole time; what was wrong is
//! that the line next to it was the wallet vouching for the number rather than
//! saying where it came from.
//!
//! Two things are pinned here. Far above the wallet's own rate for the size,
//! the fee stops being described as the node's reliable answer. Above half a
//! HAC of base fee it is refused outright, because that is not a fee.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use hacash_wallet_core::l1_fee::estimate_l1_fee;
use hacash_wallet_core::node::NodeClient;
use hacash_wallet_core::send_options::L1FeeSpeed;
use hacash_wallet_core::type4_fee::FeeGuess;
use serde_json::{Value, json};

/// The size of an ordinary signed HAC send, so the numbers below are the
/// numbers a real payment would meet.
const HAC_SEND_WIRE_BYTES: usize = 263;

#[derive(Clone)]
struct Quote {
    feasible: &'static str,
    calls: Arc<AtomicUsize>,
}

async fn fee_average(State(quote): State<Quote>) -> Json<Value> {
    quote.calls.fetch_add(1, Ordering::SeqCst);
    Json(json!({ "ret": 0, "feasible": quote.feasible, "purity": 6024 }))
}

async fn create_transaction(_body: String) -> Json<Value> {
    Json(json!({ "ret": 0, "body": "ab".repeat(110) }))
}

async fn balance(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let address = query.get("address").cloned().unwrap_or_default();
    Json(json!({
        "ret": 0,
        "list": [{ "address": address, "hacash": "1000", "satoshi": 0, "diamonds": "" }]
    }))
}

async fn spawn_node(
    feasible: &'static str,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let quote = Quote {
        feasible,
        calls: Arc::clone(&calls),
    };
    let app = Router::new()
        .route("/query/balance", get(balance))
        .route("/query/fee/average", get(fee_average))
        .route("/create/transaction", post(create_transaction))
        .with_state(quote);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock node");
    let address = listener.local_addr().expect("mock node address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock node");
    });
    (format!("http://{address}"), calls, server)
}

/// THE BASELINE. A real quote from the official endpoint must stay clean, or
/// the guard is an outage rather than a defence.
#[tokio::test]
async fn a_real_quote_is_still_a_measured_quote() {
    // The value nodeapi.hacash.org actually returns.
    let (url, calls, server) = spawn_node("0.0033132").await;
    let node = NodeClient::new(&url).expect("node client");

    let est = estimate_l1_fee(&node, HAC_SEND_WIRE_BYTES, L1FeeSpeed::Normal)
        .await
        .expect("a real quote must be accepted");
    assert!(
        !est.is_degraded(),
        "a believable node quote must not be marked a guess: {:?}",
        est.provenance
    );
    assert_eq!(est.warning(), None);
    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "the node was actually asked"
    );
    server.abort();
}

/// THE ATTACK, EXACTLY AS IT WAS RUN. `feasible: 1.0` against a real 0.001.
#[tokio::test]
async fn a_thousandfold_inflated_quote_is_refused_rather_than_displayed() {
    let (url, _calls, server) = spawn_node("1.0").await;
    let node = NodeClient::new(&url).expect("node client");

    let error = estimate_l1_fee(&node, HAC_SEND_WIRE_BYTES, L1FeeSpeed::Normal)
        .await
        .expect_err("a fee larger than the payment must not reach a signature");
    let error = error.to_string();
    assert!(
        error.contains("node_fee_quote_implausible"),
        "the refusal must be identifiable: {error}"
    );
    assert!(
        error.contains("run Hacash on your own computer"),
        "a refusal with no next step is a dead end: {error}"
    );
    server.abort();
}

/// THE MIDDLE, which is the harder half. A quote high enough to be wrong but
/// low enough to be conceivable is still shown, because refusing everything
/// unusual would strand people on a busy chain. What changes is the line
/// beside it: the wallet stops calling it "Quoted by the node".
#[tokio::test]
async fn a_quote_far_above_the_wallets_own_rate_stops_being_vouched_for() {
    // 0.05 HAC on a 263-byte send is roughly 287 times the wallet's own rate
    // for that size, and about fifteen times the largest honest quote observed.
    let (url, _calls, server) = spawn_node("0.05").await;
    let node = NodeClient::new(&url).expect("node client");

    let est = estimate_l1_fee(&node, HAC_SEND_WIRE_BYTES, L1FeeSpeed::Normal)
        .await
        .expect("a conceivable fee is still quoted, not refused");
    assert!(est.is_degraded(), "{:?}", est.provenance);
    let guesses = est.provenance.guesses();
    assert_eq!(guesses.len(), 1, "{guesses:?}");
    match &guesses[0] {
        FeeGuess::NodeQuoteFarAboveFloor { multiple } => assert!(
            *multiple >= 100,
            "the multiple has to be the real one so a person can judge it: {multiple}"
        ),
        other => panic!("wrong guess recorded: {other:?}"),
    }

    let warning = est
        .warning()
        .expect("a doubted fee has a line for the user");
    assert!(
        warning.contains("times the wallet's own rate"),
        "the line must say what is odd about the number: {warning}"
    );
    assert!(
        !warning.contains("too low to confirm"),
        "this fee is too HIGH; telling the person it may be too low is worse than silence: {warning}"
    );
    server.abort();
}
