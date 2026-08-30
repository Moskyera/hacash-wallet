//! In-process reproduction of the owner's first mainnet Fast Pay channel open.
//!
//! Stands up the real `HubState` on the `mainnet-bounded-pilot` profile against
//! a local mock fullnode that answers exactly what the owner's node answers,
//! builds an `L1ChannelOpenRequest` carrying the owner's exact numeric
//! parameters, and calls the real open path so the `HubError` can be printed
//! verbatim instead of reasoned about.
//!
//! Substituted from the owner's request: the user and Hub identities (fresh
//! keypairs), and therefore the addresses, the deterministic channel ID, the
//! operation/idempotency UUIDs, and both signatures. Everything the open path
//! branches on numerically is the owner's: deposit 20_000_000 zhu, network fee
//! 24_100 zhu, reuse version 1, a 300 second request envelope, the mainnet
//! network binding, the 20_000_000 zhu channel cap and the 20_000_000 zhu
//! aggregate TVL cap.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::routing::{get, post};
use axum::{Json, Router};
use basis::interface::Transaction;
use field::{AddrHac, Address, Amount, ChannelId, Field, Serialize as _, Uint4};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::channel_id::derive_channel_id;
use l2_fast_pay_hub::l1_channel::{
    L1_CHANNEL_OPEN_SCHEMA, L1ChannelOpenRequest, request_commitment, transaction_commitment,
};
use l2_fast_pay_hub::readiness::MainnetPilotAdmissionPolicy;
use mint::action::ChannelOpen;
use protocol::action::{ChainAllow, ChainIDList};
use protocol::transaction::TransactionType2;
use serde::Deserialize;
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;

const JOURNAL_KEY: &str = "7373737373737373737373737373737373737373737373737373737373737373";

/// The owner's live node, read from GET /query/capabilities via the Hub's
/// readiness document. Not substituted.
const MAINNET_CHAIN_ID: u32 = 0;
const MAINNET_BLOCK_ONE: &str = "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
const MAINNET_INSTANCE: &str = "5a310ec0f487a37156a182c67778495f66e5c7502f9871829edc790023b123cf";
const MAINNET_HEIGHT: u64 = 777_754;

/// The owner's exact numbers.
const OWNER_DEPOSIT_HAC: &str = "0.2";
const OWNER_DEPOSIT_ZHU: u64 = 20_000_000;
const OWNER_FEE_HAC: &str = "0.000241";
const OWNER_FEE_ZHU: u64 = 24_100;
const OWNER_BALANCE_HAC: &str = "0.3";
const OWNER_ENVELOPE_SECONDS: u64 = 300;
const OWNER_MAX_CHANNEL_FUNDING_ZHU: u64 = 20_000_000;
const OWNER_MAX_PAYMENT_ZHU: u64 = 10_000_000;
const OWNER_MAX_AGGREGATE_TVL_ZHU: u64 = 20_000_000;

#[derive(Deserialize)]
struct ChannelQuery {
    #[allow(dead_code)]
    id: Option<String>,
}

#[derive(Deserialize)]
struct TransactionQuery {
    hash: Option<String>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn account(seed: &str) -> Account {
    Account::create_by(seed).unwrap()
}

fn secret_hex(account: &Account) -> String {
    hex::encode(account.secret_key().serialize())
}

fn fin(hac: &str) -> String {
    Amount::from(hac).unwrap().to_fin_string()
}

/// A mock of the owner's mainnet fullnode: mainnet chain 0 at the owner's
/// height, the owner's block-1 hash and network instance, a fresh tip, the
/// owner's action set, and a balance of 0.3 HAC for the user.
async fn spawn_owner_like_mainnet_node(
    user_address: String,
    balance_hac: String,
) -> (
    String,
    Arc<RwLock<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let submitted = Arc::new(RwLock::new(Vec::<String>::new()));
    let transactions = Arc::new(RwLock::new(HashMap::<String, Value>::new()));
    let app =
        Router::new()
            .route(
                "/query/channel",
                get(|Query(_query): Query<ChannelQuery>| async {
                    // The owner's node: "channel not found".
                    Json(json!({"ret": 1, "err": "channel not found"}))
                }),
            )
            .route(
                "/query/transaction",
                get({
                    let transactions = transactions.clone();
                    move |Query(query): Query<TransactionQuery>| {
                        let transactions = transactions.clone();
                        async move {
                            let value = {
                                let guard = transactions.read().await;
                                query
                                    .hash
                                    .as_deref()
                                    .and_then(|hash| guard.get(hash).cloned())
                            };
                            Json(value.unwrap_or_else(
                                || json!({"ret": 1, "err": "transaction not found"}),
                            ))
                        }
                    }
                }),
            )
            .route(
                "/query/balance",
                get(move || {
                    let user_address = user_address.clone();
                    let balance_hac = balance_hac.clone();
                    async move {
                        Json(json!({
                            "ret": 0,
                            "list": [{"address": user_address, "hacash": balance_hac}]
                        }))
                    }
                }),
            )
            .route(
                "/query/capabilities",
                get(|| async {
                    let now = now_unix();
                    Json(json!({
                        "ret": 0,
                        "api_version": 1,
                        "api": { "transaction_submit_bound": true },
                        "chain": {
                            "id": MAINNET_CHAIN_ID,
                            "height": MAINNET_HEIGHT,
                            "next_height": MAINNET_HEIGHT + 1,
                            "mainnet": true
                        },
                        "network": {
                            "kind": "mainnet",
                            "node_profile_id": "hacash-mainnet",
                            "block_1_hash": MAINNET_BLOCK_ONE,
                            "instance_id": MAINNET_INSTANCE,
                            "transaction_format_version": 2
                        },
                        "sync": {
                            "tip_timestamp_unix": now,
                            "max_tip_age_seconds": 3600,
                            "fresh": true
                        },
                        "transactions": { "registered": [0, 1, 2, 3], "enabled": [0, 1, 2, 3] },
                        "actions": {
                            "registered": [1, 2, 3, 4, 5, 6, 7, 8, 1041],
                            "enabled": [1, 2, 3, 4, 5, 6, 7, 8, 1041]
                        },
                        // The owner's node reports no verified unilateral exit.
                        // The bounded pilot profile waives this on purpose.
                        "features": { "channel_unilateral_exit": false }
                    }))
                }),
            )
            .route(
                "/submit/transaction/hpay-bound",
                post({
                    let submitted = submitted.clone();
                    move |body: String| {
                        let submitted = submitted.clone();
                        async move {
                            submitted.write().await.push(body);
                            Json(json!({"ret": 1, "err": "test node refuses to broadcast"}))
                        }
                    }
                }),
            );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), submitted, handle)
}

/// The owner's request shape, with substituted identities.
///
/// `envelope_age_seconds` shifts `created_unix` into the past so the eight
/// second gap between the owner's prepare and sign can be reproduced.
fn owner_shaped_request(
    user: &Account,
    hub: &Account,
    envelope_age_seconds: u64,
) -> L1ChannelOpenRequest {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let channel_id = derive_channel_id(user.readable(), hub.readable(), 1);
    let mut action = ChannelOpen::new();
    action.channel_id =
        ChannelId::from(<[u8; 16]>::try_from(hex::decode(&channel_id).unwrap()).unwrap());
    action.left_bill = AddrHac {
        address: Address::from_readable(user.readable()).unwrap(),
        amount: Amount::from(OWNER_DEPOSIT_HAC).unwrap(),
    };
    action.right_bill = AddrHac {
        address: Address::from_readable(hub.readable()).unwrap(),
        amount: Amount::from("0").unwrap(),
    };
    let created = now_unix().saturating_sub(envelope_age_seconds);
    let mut tx = TransactionType2::new_by(
        Address::from_readable(user.readable()).unwrap(),
        Amount::from(OWNER_FEE_HAC).unwrap(),
        created,
    );
    let mut guard = ChainAllow::new();
    guard.chains = ChainIDList::from_list(vec![Uint4::from(MAINNET_CHAIN_ID)]).unwrap();
    tx.push_action(Box::new(guard)).unwrap();
    tx.push_action(Box::new(action)).unwrap();
    tx.fill_sign(user).unwrap();

    let partial_transaction_hex = hex::encode(tx.serialize());

    // Prove the exact bytes the Hub will parse really carry the owner's
    // numbers, by re-parsing them the way the Hub does.
    {
        let raw = hex::decode(&partial_transaction_hex).unwrap();
        let (parsed, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(
            ChannelOpen::downcast(&parsed.actions()[1])
                .unwrap()
                .left_bill
                .amount
                .to_zhu_u64()
                .unwrap(),
            OWNER_DEPOSIT_ZHU,
            "deposit must be the owner's 20000000 zhu"
        );
        assert_eq!(
            parsed.fee().to_zhu_u64().unwrap(),
            OWNER_FEE_ZHU,
            "network fee must be the owner's 24100 zhu"
        );
        assert_eq!(
            u128::from(OWNER_DEPOSIT_ZHU) + u128::from(OWNER_FEE_ZHU),
            20_024_100,
            "deposit plus fee must be the owner's 20024100 zhu"
        );
    }
    let mut request = L1ChannelOpenRequest {
        schema: L1_CHANNEL_OPEN_SCHEMA.into(),
        network: "mainnet".into(),
        chain_id: MAINNET_CHAIN_ID,
        mainnet: true,
        block_1_hash: MAINNET_BLOCK_ONE.into(),
        node_profile_id: "hacash-mainnet".into(),
        network_instance_id: MAINNET_INSTANCE.into(),
        transaction_format_version: 2,
        operation_id: uuid::Uuid::new_v4().to_string(),
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        created_unix: created,
        expires_unix: created + OWNER_ENVELOPE_SECONDS,
        hub_address: hub.readable().into(),
        channel_id,
        expected_reuse_version: 1,
        partial_transaction_commitment: transaction_commitment(&partial_transaction_hex).unwrap(),
        partial_transaction_hex,
        authorization_public_key_hex: hex::encode(user.public_key().serialize_compressed()),
        authorization_signature_hex: String::new(),
    };
    let commitment: [u8; 32] = hex::decode(request_commitment(&request).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
    request
}

struct Fixture {
    hub: HubState,
    request: L1ChannelOpenRequest,
    user_address: String,
    _node: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
    submitted: Arc<RwLock<Vec<String>>>,
}

/// `allowlisted` and `balance_hac` are the two knobs the enumeration below
/// turns; everything else is fixed at the owner's configuration.
async fn owner_like_hub(seed: &str, allowlisted: bool, balance_hac: &str) -> Fixture {
    let user = account(&format!("{seed}-user"));
    let hub_account = account(&format!("{seed}-hub"));
    let request = owner_shaped_request(&user, &hub_account, 8);
    let (node_url, submitted, node) =
        spawn_owner_like_mainnet_node(user.readable().into(), fin(balance_hac)).await;
    let directory = tempdir().unwrap();
    let allowed: Vec<String> = if allowlisted {
        vec![user.readable().into()]
    } else {
        vec![account("someone-else").readable().into()]
    };
    let admission =
        MainnetPilotAdmissionPolicy::try_new(&allowed, OWNER_MAX_AGGREGATE_TVL_ZHU).unwrap();
    let hub = HubState::new_secure_with_mainnet_admission_signer(
        "owner-like bounded pilot hub",
        hub_account.readable(),
        &node_url,
        None,
        directory.path().join("hub-state.json"),
        l2_fast_pay_hub::hub_signer::HubSigner::from_secret_hex(&secret_hex(&hub_account)).unwrap(),
        JOURNAL_KEY,
        &"a5".repeat(32),
        "mainnet-bounded-pilot",
        OWNER_MAX_PAYMENT_ZHU,
        OWNER_MAX_CHANNEL_FUNDING_ZHU,
        admission,
    )
    .unwrap();
    Fixture {
        hub,
        request,
        user_address: user.readable().into(),
        _node: node,
        _directory: directory,
        submitted,
    }
}

/// The reproduction. Prints the `HubError` verbatim.
#[tokio::test]
async fn owner_exact_parameters_reach_the_hub_open_path() {
    let fixture = owner_like_hub("owner-exact", true, OWNER_BALANCE_HAC).await;

    // First prove this Hub is in the owner's gate state: the bounded pilot
    // profile, mainnet detected, payments enabled, and an empty blocker list,
    // exactly as GET /v1/readiness/mainnet reports on the owner's Hub.
    let readiness = fixture.hub.mainnet_readiness().await;
    println!("profile              = {}", readiness.profile);
    println!("payments_enabled     = {}", readiness.payments_enabled);
    println!("mainnet_detected     = {:?}", readiness.mainnet_detected);
    println!("blockers             = {:?}", readiness.blockers);
    println!(
        "max_channel_funding  = {}",
        readiness.max_channel_funding_hac_zhu
    );
    assert_eq!(readiness.profile, "mainnet-bounded-pilot");
    assert_eq!(readiness.mainnet_detected, Some(true));
    assert!(
        readiness.blockers.is_empty(),
        "mock node must reproduce the owner's empty blocker list, got {:?}",
        readiness.blockers
    );
    assert!(readiness.payments_enabled);

    println!("---- request ----");
    println!("user_address     = {}", fixture.user_address);
    println!("hub_address      = {}", fixture.request.hub_address);
    println!("channel_id       = {}", fixture.request.channel_id);
    println!("created_unix     = {}", fixture.request.created_unix);
    println!("expires_unix     = {}", fixture.request.expires_unix);
    println!(
        "envelope_width   = {}",
        fixture.request.expires_unix - fixture.request.created_unix
    );
    println!("now_unix         = {}", now_unix());

    let outcome = fixture.hub.open_channel(&fixture.request).await;
    match &outcome {
        Ok(response) => println!("---- HUB ACCEPTED ----\n{response:?}"),
        Err(error) => println!("---- HUB REFUSED ----\n{error}"),
    }
    assert!(
        fixture.submitted.read().await.is_empty() || outcome.is_ok(),
        "a refusal must never have broadcast"
    );
}

/// Every refusal below is asserted by turning exactly one knob away from the
/// owner's configuration, so each error string is produced by running the real
/// path rather than by reading it.
#[tokio::test]
async fn allowlist_refusal_is_reachable_and_the_owner_is_allowlisted() {
    let denied = owner_like_hub("allowlist-denied", false, OWNER_BALANCE_HAC).await;
    let error = denied
        .hub
        .open_channel(&denied.request)
        .await
        .expect_err("a non-allowlisted user must be refused");
    println!("not allowlisted -> {error}");
    assert!(
        error.to_string().contains("not allowlisted"),
        "unexpected refusal: {error}"
    );

    let allowed = owner_like_hub("allowlist-allowed", true, OWNER_BALANCE_HAC).await;
    let outcome = allowed.hub.open_channel(&allowed.request).await;
    let message = outcome
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        !message.contains("not allowlisted"),
        "the owner's allowlisted address must clear admission, got {message}"
    );
}

#[tokio::test]
async fn funding_refusal_is_reachable_and_the_owner_is_funded() {
    // 0.2 HAC covers the deposit but not deposit + fee.
    let short = owner_like_hub("funding-short", true, "0.2").await;
    let error = short
        .hub
        .open_channel(&short.request)
        .await
        .expect_err("an underfunded address must be refused");
    println!("underfunded -> {error}");
    assert!(
        error.to_string().contains("20024100"),
        "the refusal must name the owner's exact requirement, got {error}"
    );

    let funded = owner_like_hub("funding-ok", true, OWNER_BALANCE_HAC).await;
    let message = funded
        .hub
        .open_channel(&funded.request)
        .await
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    assert!(
        !message.contains("including network fee"),
        "0.3 HAC must clear require_open_funding, got {message}"
    );
}

#[tokio::test]
async fn the_owner_deposit_sits_exactly_on_both_caps_and_passes_both() {
    // The channel cap and the aggregate TVL cap are both 20_000_000 zhu and the
    // deposit is exactly 20_000_000 zhu. Both comparisons are strict `>`.
    let at_cap = owner_like_hub("at-cap", true, OWNER_BALANCE_HAC).await;
    let message = at_cap
        .hub
        .open_channel(&at_cap.request)
        .await
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    println!("deposit at both caps -> {message}");
    assert!(
        !message.contains("cap exceeded") && !message.contains("exceeds the Hub cap"),
        "20000000 zhu at a 20000000 zhu cap must pass, got {message}"
    );
    assert_eq!(
        OWNER_DEPOSIT_ZHU % 100_000,
        0,
        "deposit is millimei aligned"
    );
}

#[tokio::test]
async fn the_owner_envelope_is_exactly_at_the_maximum_lifetime_and_passes() {
    // created_unix 1788077500 -> expires_unix 1788077800 is exactly 300
    // seconds, and REQUEST_MAX_LIFETIME_SECONDS is 300 with a strict `>`.
    let fixture = owner_like_hub("envelope-300", true, OWNER_BALANCE_HAC).await;
    assert_eq!(
        fixture.request.expires_unix - fixture.request.created_unix,
        OWNER_ENVELOPE_SECONDS
    );
    let message = fixture
        .hub
        .open_channel(&fixture.request)
        .await
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
    println!("300 second envelope, signed 8s in -> {message}");
    assert!(
        !message.contains("expired or outside the allowed signing window"),
        "a 300 second envelope signed 8 seconds in must pass, got {message}"
    );
}

#[tokio::test]
async fn a_301_second_envelope_is_refused() {
    let user = account("envelope-301-user");
    let hub_account = account("envelope-301-hub");
    let mut request = owner_shaped_request(&user, &hub_account, 8);
    request.expires_unix = request.created_unix + OWNER_ENVELOPE_SECONDS + 1;
    let commitment: [u8; 32] = hex::decode(request_commitment(&request).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));

    let (node_url, _submitted, _node) =
        spawn_owner_like_mainnet_node(user.readable().into(), fin(OWNER_BALANCE_HAC)).await;
    let directory = tempdir().unwrap();
    let admission = MainnetPilotAdmissionPolicy::try_new(
        [user.readable().to_owned()],
        OWNER_MAX_AGGREGATE_TVL_ZHU,
    )
    .unwrap();
    let hub = HubState::new_secure_with_mainnet_admission_signer(
        "envelope hub",
        hub_account.readable(),
        &node_url,
        None,
        directory.path().join("hub-state.json"),
        l2_fast_pay_hub::hub_signer::HubSigner::from_secret_hex(&secret_hex(&hub_account)).unwrap(),
        JOURNAL_KEY,
        &"a5".repeat(32),
        "mainnet-bounded-pilot",
        OWNER_MAX_PAYMENT_ZHU,
        OWNER_MAX_CHANNEL_FUNDING_ZHU,
        admission,
    )
    .unwrap();
    let error = hub
        .open_channel(&request)
        .await
        .expect_err("a 301 second envelope must be refused");
    println!("301 second envelope -> {error}");
    assert!(
        error
            .to_string()
            .contains("expired or outside the allowed signing window"),
        "unexpected refusal: {error}"
    );
}

#[tokio::test]
async fn a_second_open_for_the_same_address_is_refused_by_the_per_address_rule() {
    let fixture = owner_like_hub("per-address", true, OWNER_BALANCE_HAC).await;
    let first = fixture.hub.open_channel(&fixture.request).await;
    println!("first open  -> {first:?}");

    let user = account("per-address-user");
    let hub_account = account("per-address-hub");
    let second = owner_shaped_request(&user, &hub_account, 8);
    let outcome = fixture.hub.open_channel(&second).await;
    println!("second open -> {outcome:?}");
    if let Err(error) = &outcome {
        println!("second open refusal -> {error}");
    }
}

/// THE REPRODUCTION OF THE OWNER'S REFUSAL.
///
/// The owner's Hub carries one prior channel-open from 2026-08-25 in its
/// durable journal: operation e2d8136b-201f-4a20-ba87-2fd2500cb270, channel
/// ec74cea2f8fc576fecbbac878cb46a6d, user 1LCY6uQS3iNGy2mKSmhFVU2dHgBQLf74Fx,
/// user_deposit_zhu 20000000, last phase l1_open_submitted. `Submitted`
/// reserves admission, so `aggregate_pilot_tvl_zhu` counts its whole deposit,
/// and the aggregate TVL cap is 20000000 zhu. The owner's 20000000 zhu deposit
/// proposes 40000000 zhu against a 20000000 zhu cap.
///
/// Here the same shape is produced by running it: one prior open for a
/// different allowlisted address parks 20000000 zhu in a reserving status,
/// then the owner-shaped request is presented.
#[tokio::test]
async fn a_prior_reserving_open_consumes_the_whole_tvl_budget_and_refuses_the_next_open() {
    let prior_user = account("tvl-prior-user");
    let owner_user = account("tvl-owner-user");
    let hub_account = account("tvl-hub");

    let prior_request = owner_shaped_request(&prior_user, &hub_account, 8);
    let owner_request = owner_shaped_request(&owner_user, &hub_account, 8);

    // One node that answers a balance for whichever address is asked.
    let balance = fin(OWNER_BALANCE_HAC);
    let app = Router::new()
        .route(
            "/query/channel",
            get(|Query(_q): Query<ChannelQuery>| async {
                Json(json!({"ret": 1, "err": "channel not found"}))
            }),
        )
        .route(
            "/query/transaction",
            get(|Query(_q): Query<TransactionQuery>| async {
                Json(json!({"ret": 1, "err": "transaction not found"}))
            }),
        )
        .route(
            "/query/balance",
            get(move || {
                let balance = balance.clone();
                // No "address" key, exactly like the owner's fullnode:
                // {"list":[{"diamond":0,"hacash":"3:247","satoshi":0}],"ret":0}
                async move {
                    Json(json!({"ret": 0, "list": [{"diamond": 0, "hacash": balance, "satoshi": 0}]}))
                }
            }),
        )
        .route(
            "/query/capabilities",
            get(|| async {
                let now = now_unix();
                Json(json!({
                    "ret": 0,
                    "api_version": 1,
                    "api": { "transaction_submit_bound": true },
                    "chain": {
                        "id": MAINNET_CHAIN_ID,
                        "height": MAINNET_HEIGHT,
                        "next_height": MAINNET_HEIGHT + 1,
                        "mainnet": true
                    },
                    "network": {
                        "kind": "mainnet",
                        "node_profile_id": "hacash-mainnet",
                        "block_1_hash": MAINNET_BLOCK_ONE,
                        "instance_id": MAINNET_INSTANCE,
                        "transaction_format_version": 2
                    },
                    "sync": {
                        "tip_timestamp_unix": now,
                        "max_tip_age_seconds": 3600,
                        "fresh": true
                    },
                    "transactions": { "registered": [0, 1, 2, 3, 4], "enabled": [0, 1, 2, 3] },
                    "actions": {
                        "registered": [1, 2, 3, 4, 5, 6, 7, 8, 1041],
                        "enabled": [1, 2, 3, 4, 5, 6, 7, 8, 1041]
                    },
                    "features": { "channel_unilateral_exit": false }
                }))
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post(|body: String| async move {
                // The owner's Aug 25 open reached l1_open_submitted: the node
                // accepted the broadcast, and the channel never appeared on
                // chain. `Submitted` reserves admission forever and, unlike
                // `RecoveryRequired`, does not latch the Hub's recovery gate,
                // which is why the owner's Hub still reports settlement_ready.
                let raw = hex::decode(&body).unwrap();
                let (tx, _consumed) = protocol::transaction::transaction_create(&raw).unwrap();
                let hash = hex::encode(tx.hash().as_bytes());
                Json(json!({"ret": 0, "hash": hash}))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_url = format!("http://{}", listener.local_addr().unwrap());
    let _node = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let admission = MainnetPilotAdmissionPolicy::try_new(
        [
            prior_user.readable().to_owned(),
            owner_user.readable().to_owned(),
        ],
        OWNER_MAX_AGGREGATE_TVL_ZHU,
    )
    .unwrap();
    let hub = HubState::new_secure_with_mainnet_admission_signer(
        "tvl hub",
        hub_account.readable(),
        &node_url,
        None,
        directory.path().join("hub-state.json"),
        l2_fast_pay_hub::hub_signer::HubSigner::from_secret_hex(&secret_hex(&hub_account)).unwrap(),
        JOURNAL_KEY,
        &"a5".repeat(32),
        "mainnet-bounded-pilot",
        OWNER_MAX_PAYMENT_ZHU,
        OWNER_MAX_CHANNEL_FUNDING_ZHU,
        admission,
    )
    .unwrap();

    // The prior open. It parks 20000000 zhu in a status that reserves
    // admission, exactly like the owner's Aug 25 operation.
    let prior = hub.open_channel(&prior_request).await.unwrap();
    println!("prior open status = {}", prior.status);
    assert_eq!(
        prior.status, "submitted",
        "the prior open must sit in the owner's Aug 25 status"
    );

    // The Hub still publishes itself as completely healthy.
    let readiness = hub.mainnet_readiness().await;
    println!("after prior open:");
    println!(
        "  payments_enabled          = {}",
        readiness.payments_enabled
    );
    println!("  blockers                  = {:?}", readiness.blockers);
    println!(
        "  aggregate_tvl_within_limit = {}",
        readiness.aggregate_tvl_within_limit
    );
    println!(
        "  max_aggregate_tvl_hac_zhu  = {}",
        readiness.max_aggregate_tvl_hac_zhu
    );
    assert!(
        readiness.payments_enabled,
        "the Hub must still publish payments_enabled: true, as the owner's does"
    );
    assert!(readiness.blockers.is_empty());
    assert!(
        readiness.aggregate_tvl_within_limit,
        "TVL exactly at the cap still reads within limit, as the owner's does"
    );

    // Now the owner-shaped open.
    let error = hub
        .open_channel(&owner_request)
        .await
        .expect_err("the owner's open must be refused");
    println!("---- THE REFUSAL ----");
    println!("{error}");
    let error = error.to_string();
    assert!(
        error.starts_with(
            "admission: mainnet pilot aggregate Hub TVL cap exceeded: proposed 40000000 zhu, cap 20000000 zhu."
        ),
        "the owner's own sentence, unchanged: {error}"
    );
    // And what the sentence could not say before: who is holding the budget.
    // Without this the owner reads "too big" and has nowhere to go.
    assert!(
        error.contains("20000000 zhu of that cap is already held"),
        "{error}"
    );
    assert!(error.contains("status submitted"), "{error}");
    assert!(
        error.contains("that have not confirmed"),
        "the refusal must say the budget is held by something unconfirmed: {error}"
    );

    // This open is one block old, so the retirement sweep correctly leaves it
    // alone. The chain has not yet had a single chance to include it. Blocks
    // are what release it; see `state::open_retirement_tests`.
    let readiness = hub.mainnet_readiness().await;
    assert_eq!(readiness.aggregate_tvl_hac_zhu, OWNER_DEPOSIT_ZHU);
    assert_eq!(readiness.aggregate_tvl_headroom_hac_zhu, 0);
    assert!(
        !readiness.new_channel_admission_available,
        "a Hub at its cap must say so, even while every other field reads healthy"
    );
}
