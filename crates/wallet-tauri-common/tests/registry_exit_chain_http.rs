//! The exit's chain view, over real HTTP, against a fullnode that misbehaves.
//!
//! # What was missing
//!
//! `crate::agent_registry_exit::FullnodeRegistryExitChain` is the only
//! implementation of `HvmRegistryExitChainV1` that ever talks to a real
//! fullnode, and it had no test of any kind. The on-chain exit proof in
//! `agent-wallet-core` drives a different implementation of the same trait, an
//! in-process `MemChain` view, so every line of the HTTP one, including the
//! part that decides whether signed bytes get handed over again, was
//! unexercised.
//!
//! # Why these cases and not a happy path
//!
//! The happy path is not where this module can cost anybody money. One method
//! here decides between three answers that are not interchangeable:
//!
//! * `Unknown` makes the driver hand the stored bytes to a node again;
//! * `Pending` makes it wait;
//! * `Mined` retires the step.
//!
//! A node that is merely unreachable, or that answers with an error, must
//! never come out as `Unknown`. The module's own documentation states that
//! rule; nothing checked it. Everything below is that rule and its siblings,
//! served by a real HTTP server on a real socket so the reqwest, status-code
//! and JSON paths are the ones a person's fullnode would take.
//!
//! Nothing here signs, and nothing here reaches a chain.

#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use hacash_wallet_core::WalletError;
use hacash_wallet_core::hvm_registry_exit_driver::{
    HvmRegistryExitChainV1, HvmRegistryExitSightingV1,
};
use l2_fast_pay_hub::hvm_registry::HvmRegistryBindingV2;
use serde_json::{Value, json};
use wallet_tauri_common::agent_registry_exit::FullnodeRegistryExitChain;

/// What the pretend fullnode answers with, and how often it was asked.
#[derive(Default)]
struct Fullnode {
    transaction: std::sync::Mutex<Value>,
    transaction_status: std::sync::Mutex<StatusCode>,
    submit_status: std::sync::Mutex<StatusCode>,
    submits: AtomicUsize,
}

async fn capabilities_route() -> Json<Value> {
    Json(json!({
        "ret": 0,
        "api_version": 1,
        "chain": { "id": 7, "height": 900, "next_height": 901, "mainnet": false },
        "network": {
            "kind": "testnet",
            "node_profile_id": "local",
            "block_1_hash": "0".repeat(64),
            "transaction_format_version": 1,
            "instance_id": "1".repeat(32),
        },
        "sync": {
            "tip_timestamp_unix": now_unix(),
            "max_tip_age_seconds": 3_600,
            "fresh": true,
        },
        "actions": { "registered": [14, 44], "enabled": [14, 44] },
        "transactions": { "enabled": [2, 3] },
        "api": { "transaction_submit_bound": true, "hpay_channel_registry_query": true },
    }))
}

async fn transaction_route(State(node): State<Arc<Fullnode>>) -> (StatusCode, Json<Value>) {
    let status = *node.transaction_status.lock().unwrap();
    (status, Json(node.transaction.lock().unwrap().clone()))
}

async fn submit_route(State(node): State<Arc<Fullnode>>) -> (StatusCode, Json<Value>) {
    node.submits.fetch_add(1, Ordering::SeqCst);
    let status = *node.submit_status.lock().unwrap();
    if status.is_success() {
        (status, Json(json!({ "ret": 0, "hash": HASH })))
    } else {
        (status, Json(json!({ "ret": 1, "err": "mempool refused" })))
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A binding that genuinely passes `HvmRegistryBindingV2::validate`.
///
/// It has to. `submit_hvm_registry_transaction_bound` validates the binding
/// before it opens a socket, so an invalid one would make every submission
/// fail without a request ever leaving the process, and the duplicate-handling
/// assertions below would then pass for a reason that has nothing to do with
/// what they are about. The submission counter at the end of that test is what
/// keeps that honest.
fn binding() -> HvmRegistryBindingV2 {
    HvmRegistryBindingV2 {
        schema: l2_fast_pay_hub::hvm_registry::HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: l2_fast_pay_hub::hvm_registry::HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: 7,
        network_instance_id: "11".repeat(32),
        contract_address: vm::ContractAddress::from_unchecked(field::Address::create_contract(
            [9; 20],
        ))
        .to_readable(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: l2_fast_pay_hub::hvm_registry::HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: "33".repeat(16),
        reuse_version: 0,
        left_address: field::Address::from(
            *sys::Account::create_by_password("left")
                .expect("left key")
                .address(),
        )
        .to_readable(),
        right_hub_address: field::Address::from(
            *sys::Account::create_by_password("hub")
                .expect("hub key")
                .address(),
        )
        .to_readable(),
        left_deposit_zhu: 5_000_000_000,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    }
}

/// The fixture is only a fixture if the real validator accepts it.
#[test]
fn the_fixture_binding_is_one_this_workspace_would_actually_accept() {
    binding()
        .validate()
        .expect("the test binding must be valid");
}

async fn serve(node: Arc<Fullnode>) -> SocketAddr {
    let app = Router::new()
        .route("/query/capabilities", get(capabilities_route))
        .route("/query/transaction", get(transaction_route))
        .route("/submit/transaction/hpay-bound", post(submit_route))
        .with_state(node);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    address
}

fn confirmed(block: Value) -> Value {
    let mut answer = json!({
        "ret": 0,
        "hash": HASH,
        "tx_type": 3,
        "actions": [{ "kind": 44 }],
        "signatures": [{ "publickey": "00" }],
        "body": "abcd",
        "pending": false,
        "confirm": 6,
    });
    answer["block"] = block;
    answer
}

/// The three sightings are not interchangeable, and a broken node must not be
/// able to produce the one that re-sends bytes.
#[tokio::test]
async fn a_node_that_will_not_answer_never_reads_as_a_missing_transaction() {
    let node = Arc::new(Fullnode {
        transaction: std::sync::Mutex::new(json!({ "ret": 0 })),
        transaction_status: std::sync::Mutex::new(StatusCode::OK),
        submit_status: std::sync::Mutex::new(StatusCode::OK),
        submits: AtomicUsize::new(0),
    });
    let address = serve(node.clone()).await;
    let chain = FullnodeRegistryExitChain::new(&format!("http://{address}"), binding(), 0, 0)
        .expect("view");

    // The node's own tip, read over HTTP, is what the freshness rule is
    // judged against.
    let (height, age) = chain.chain_tip().await.expect("tip");
    assert_eq!(height, 900);
    assert!(age < 60);

    // 1. The node is up but broken. This is the case that must never be
    //    `Unknown`: the driver answers `Unknown` by handing signed bytes to a
    //    node again, and a node that cannot answer is not a node that has
    //    never seen them.
    *node.transaction_status.lock().unwrap() = StatusCode::INTERNAL_SERVER_ERROR;
    let broken = chain.transaction_sighting(HASH).await;
    assert!(
        matches!(broken, Err(WalletError::Node(_))),
        "a 500 from the fullnode must fail the pass, not read as absent: {broken:?}"
    );
    *node.transaction_status.lock().unwrap() = StatusCode::OK;

    // 2. The node is up and genuinely does not have it. Only this is
    //    `Unknown`.
    *node.transaction.lock().unwrap() = json!({ "ret": 1, "err": "transaction not found" });
    assert_eq!(
        chain.transaction_sighting(HASH).await.expect("absent"),
        HvmRegistryExitSightingV1::Unknown
    );

    // 3. The node holds it and no block carries it. Waiting, not re-sending.
    *node.transaction.lock().unwrap() = json!({
        "ret": 0,
        "hash": HASH,
        "tx_type": 3,
        "actions": [{ "kind": 44 }],
        "signatures": [{ "publickey": "00" }],
        "body": "abcd",
        "pending": true,
    });
    assert_eq!(
        chain.transaction_sighting(HASH).await.expect("pending"),
        HvmRegistryExitSightingV1::Pending
    );

    // 4. Mined, with the block named. Only now may a step be retired.
    *node.transaction.lock().unwrap() = confirmed(json!({ "height": 880, "hash": "b".repeat(64) }));
    assert_eq!(
        chain.transaction_sighting(HASH).await.expect("mined"),
        HvmRegistryExitSightingV1::Mined {
            block_height: 880,
            block_hash: "b".repeat(64),
        }
    );

    // 5. A node that says "confirmed" and cannot name the block. Reading this
    //    as `Unknown` would re-send bytes that are already mined; reading it
    //    as `Mined` would write an unanchored block into the durable record.
    //    Neither is safe, so the pass fails and the next one asks again.
    *node.transaction.lock().unwrap() = confirmed(json!({ "height": 880 }));
    let unanchored = chain.transaction_sighting(HASH).await;
    assert!(
        matches!(unanchored, Err(WalletError::Node(_))),
        "a confirmation that cannot name its block is not a confirmation: {unanchored:?}"
    );
}

/// A node refusing a duplicate has done what was asked, but only if it can
/// then be seen holding the bytes.
#[tokio::test]
async fn a_rejected_submission_counts_as_sent_only_when_the_node_holds_it() {
    let node = Arc::new(Fullnode {
        transaction: std::sync::Mutex::new(json!({ "ret": 1, "err": "transaction not found" })),
        transaction_status: std::sync::Mutex::new(StatusCode::OK),
        submit_status: std::sync::Mutex::new(StatusCode::BAD_REQUEST),
        submits: AtomicUsize::new(0),
    });
    let address = serve(node.clone()).await;
    let chain = FullnodeRegistryExitChain::new(&format!("http://{address}"), binding(), 0, 0)
        .expect("view");

    // Refused, and the node does not have it. That is a real failure and must
    // be reported as one: swallowing it would let the driver mark a step
    // submitted that no node ever accepted.
    let lost = chain.submit_exit_transaction("abcd", HASH).await;
    assert!(
        matches!(lost, Err(WalletError::Node(_))),
        "a refusal from a node that does not hold the bytes is a failure: {lost:?}"
    );

    // Refused because it is a duplicate. The bytes are idempotent by hash and
    // the caller has already made them durable, so this is success.
    *node.transaction.lock().unwrap() = json!({
        "ret": 0,
        "hash": HASH,
        "tx_type": 3,
        "actions": [{ "kind": 44 }],
        "signatures": [{ "publickey": "00" }],
        "body": "abcd",
        "pending": true,
    });
    chain
        .submit_exit_transaction("abcd", HASH)
        .await
        .expect("a duplicate the node is holding is success");

    // And an ordinary acceptance is success without a second query.
    *node.submit_status.lock().unwrap() = StatusCode::OK;
    chain
        .submit_exit_transaction("abcd", HASH)
        .await
        .expect("accepted");
    assert_eq!(node.submits.load(Ordering::SeqCst), 3);
}

/// A fullnode that is not there at all.
///
/// The exit exists for the day things are broken, so the failure has to be a
/// failure rather than an answer. Nothing may come back as `Unknown` here
/// either.
#[tokio::test]
async fn an_unreachable_fullnode_fails_every_method_and_answers_none_of_them() {
    // Bind and drop, so the port is one nothing is listening on.
    let dead = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        listener.local_addr().expect("addr")
    };
    let chain =
        FullnodeRegistryExitChain::new(&format!("http://{dead}"), binding(), 0, 0).expect("view");

    assert!(chain.chain_tip().await.is_err());
    assert!(chain.registry_snapshot().await.is_err());
    let sighting = chain.transaction_sighting(HASH).await;
    assert!(
        matches!(sighting, Err(WalletError::Node(_))),
        "an unreachable node must not read as a transaction the chain has never seen: {sighting:?}"
    );
    assert!(chain.submit_exit_transaction("abcd", HASH).await.is_err());
}
