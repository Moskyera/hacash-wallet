//! A FEE THE WALLET INVENTED MUST NOT ARRIVE LOOKING LIKE A FEE THE NETWORK
//! QUOTED.
//!
//! `crates/wallet-core/src/l1_fee.rs` falls back twice when the node does not
//! answer: `base_fee_mei` drops to the wallet's own compiled-in floor purity
//! when `/query/fee/average` fails, and the size the fee is priced from drops
//! to `L1_DEFAULT_WIRE_BYTES` when `/create/transaction` cannot build the body.
//!
//! Both fallbacks are correct. Refusing to quote any fee because the node
//! blinked would be worse than quoting a minimum. What was wrong is that both
//! returned an ordinary `Ok(estimate)`, indistinguishable from a measured one,
//! so nothing above them, and nobody in front of them, could tell.
//!
//! That is not cosmetic. An under-priced transaction that sits unconfirmed
//! inside a channel challenge window loses the window, and the older and worse
//! split settles. The wallet held the node's exact error and showed a fee
//! instead.
//!
//! These tests pin the difference: the same call against a healthy node and
//! against a broken one must produce estimates that disagree about their own
//! provenance, and the broken one must carry the node's own words.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use hacash_wallet_core::l1_fee::{
    L1_DEFAULT_WIRE_BYTES, estimate_hac_l1_fee_tiers, estimate_l1_fee,
};
use hacash_wallet_core::node::NodeClient;
use hacash_wallet_core::send_options::L1FeeSpeed;
use hacash_wallet_core::type4_fee::FeeGuess;
use serde_json::{Value, json};

const SENDER: &str = "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS";
const RECIPIENT: &str = "1271FDSMxNKrxjxpKpsCgnJDCiaSSpxvJ7";

/// The exact sentence the node hands back when its fee index is not ready.
/// The point of the test is that this string, not a summary of it, reaches the
/// caller.
const FEE_QUERY_ERROR: &str = "fee average index is still building at height 774025";
const BUILD_ERROR: &str = "create transaction rejected: sender not found";

#[derive(Clone)]
struct NodeHealth {
    fee_query_works: Arc<AtomicBool>,
    build_works: Arc<AtomicBool>,
}

async fn fee_average(State(health): State<NodeHealth>) -> Json<Value> {
    if health.fee_query_works.load(Ordering::SeqCst) {
        Json(json!({ "ret": 0, "feasible": "0.0031", "purity": 6024 }))
    } else {
        // Exactly the shape a refusing node sends: a ret, a reason, and no
        // fee at all.
        Json(json!({ "ret": 1, "err": FEE_QUERY_ERROR }))
    }
}

async fn create_transaction(State(health): State<NodeHealth>, _body: String) -> Json<Value> {
    if health.build_works.load(Ordering::SeqCst) {
        // 110 unsigned bytes of anything; only the length is read.
        Json(json!({ "ret": 0, "body": "ab".repeat(110) }))
    } else {
        Json(json!({ "ret": 1, "err": BUILD_ERROR }))
    }
}

async fn balance(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let address = query.get("address").cloned().unwrap_or_default();
    Json(json!({
        "ret": 0,
        "list": [{ "address": address, "hacash": "1000", "satoshi": 0, "diamonds": "" }]
    }))
}

async fn spawn_node(health: NodeHealth) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/query/balance", get(balance))
        .route("/query/fee/average", get(fee_average))
        .route("/create/transaction", post(create_transaction))
        .with_state(health);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock node");
    let address = listener.local_addr().expect("mock node address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock node");
    });
    (format!("http://{address}"), server)
}

/// THE BASELINE. When the node answers, nothing is a guess and there is
/// nothing to warn anyone about. Without this half, a change that marked every
/// estimate degraded would still pass the interesting half below.
#[tokio::test]
async fn a_fee_the_node_quoted_says_it_was_measured() {
    let health = NodeHealth {
        fee_query_works: Arc::new(AtomicBool::new(true)),
        build_works: Arc::new(AtomicBool::new(true)),
    };
    let (url, server) = spawn_node(health).await;
    let node = NodeClient::new(&url).expect("node client");

    let est = estimate_l1_fee(&node, 263, L1FeeSpeed::Normal)
        .await
        .expect("healthy node quotes a fee");
    assert!(
        !est.is_degraded(),
        "a node-quoted fee must not be marked a guess: {:?}",
        est.provenance
    );
    assert_eq!(est.warning(), None);
    assert_eq!(est.purity, 6024, "the purity is the node's, not the floor");

    let tiers =
        estimate_hac_l1_fee_tiers(&node, SENDER, RECIPIENT, "10:248", 10.0, L1FeeSpeed::Fast)
            .await
            .expect("healthy node quotes tiers");
    assert!(!tiers.is_degraded());
    assert_eq!(tiers.warning(), None);
    assert_eq!(
        tiers.wire_bytes, 207,
        "110 unsigned bytes plus one 97-byte legacy signature"
    );

    server.abort();
}

/// THE FIX. A failed fee query still produces a fee, and now says so, in the
/// node's own words.
#[tokio::test]
async fn a_failed_fee_query_is_carried_to_the_caller_not_swallowed() {
    let health = NodeHealth {
        fee_query_works: Arc::new(AtomicBool::new(false)),
        build_works: Arc::new(AtomicBool::new(true)),
    };
    let (url, server) = spawn_node(health).await;
    let node = NodeClient::new(&url).expect("node client");

    let est = estimate_l1_fee(&node, 263, L1FeeSpeed::Normal)
        .await
        .expect("the fallback still answers, because quoting nothing is worse");

    assert!(
        est.is_degraded(),
        "the fee came from the wallet's own floor and must not look measured"
    );
    let guesses = est.provenance.guesses();
    assert_eq!(
        guesses.len(),
        1,
        "exactly one thing was guessed: {guesses:?}"
    );
    match &guesses[0] {
        FeeGuess::PurityFromLocalFloor { node_error } => assert!(
            node_error.contains(FEE_QUERY_ERROR),
            "the node's own error must survive to the caller, got: {node_error}"
        ),
        other => panic!("wrong guess recorded: {other:?}"),
    }

    let warning = est
        .warning()
        .expect("a degraded fee has a line for the user");
    assert!(
        warning.contains(FEE_QUERY_ERROR),
        "the user-facing line must name the real reason: {warning}"
    );
    assert!(
        warning.contains("too low to confirm"),
        "the user-facing line must say what the risk is: {warning}"
    );

    server.abort();
}

/// THE SECOND SILENT FALLBACK. A node that cannot build the body leaves the
/// fee priced against an assumed size, which is a guess about a different
/// number and has to be reported as its own.
#[tokio::test]
async fn a_failed_body_build_reports_the_assumed_size() {
    let health = NodeHealth {
        fee_query_works: Arc::new(AtomicBool::new(true)),
        build_works: Arc::new(AtomicBool::new(false)),
    };
    let (url, server) = spawn_node(health).await;
    let node = NodeClient::new(&url).expect("node client");

    let tiers =
        estimate_hac_l1_fee_tiers(&node, SENDER, RECIPIENT, "10:248", 10.0, L1FeeSpeed::Normal)
            .await
            .expect("the fallback still answers");

    assert!(tiers.is_degraded(), "the size was assumed, not measured");
    assert_eq!(
        tiers.wire_bytes, L1_DEFAULT_WIRE_BYTES,
        "the assumed size is the documented default"
    );
    let guesses = tiers.selected.provenance.guesses();
    assert_eq!(guesses.len(), 1, "only the size was guessed: {guesses:?}");
    match &guesses[0] {
        FeeGuess::SizeFromDefault {
            node_error,
            assumed_bytes,
        } => {
            assert!(
                node_error.contains(BUILD_ERROR),
                "the node's own build error must survive: {node_error}"
            );
            assert_eq!(*assumed_bytes, L1_DEFAULT_WIRE_BYTES);
        }
        other => panic!("wrong guess recorded: {other:?}"),
    }

    let warning = tiers.warning().expect("a degraded quote has a line");
    assert!(
        warning.contains(&L1_DEFAULT_WIRE_BYTES.to_string()),
        "the line must name the size that was assumed: {warning}"
    );

    server.abort();
}

/// BOTH AT ONCE. A node that is simply down fails both calls, and the estimate
/// has to admit both rather than only the last one it noticed.
#[tokio::test]
async fn a_node_that_is_down_admits_every_guess_it_made() {
    let health = NodeHealth {
        fee_query_works: Arc::new(AtomicBool::new(false)),
        build_works: Arc::new(AtomicBool::new(false)),
    };
    let (url, server) = spawn_node(health).await;
    let node = NodeClient::new(&url).expect("node client");

    let tiers =
        estimate_hac_l1_fee_tiers(&node, SENDER, RECIPIENT, "10:248", 10.0, L1FeeSpeed::Normal)
            .await
            .expect("the fallback still answers");

    let guesses = tiers.selected.provenance.guesses();
    assert_eq!(
        guesses.len(),
        2,
        "both the rate and the size were guessed: {guesses:?}"
    );
    let warning = tiers.warning().expect("a degraded quote has a line");
    assert!(warning.contains(FEE_QUERY_ERROR), "{warning}");
    assert!(warning.contains(BUILD_ERROR), "{warning}");

    server.abort();
}
