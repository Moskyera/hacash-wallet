//! The owner's first mainnet channel open, refused and then not refused.
//!
//! The owner's Hub was carrying one channel-open from five days earlier that
//! had been broadcast and never mined. `Submitted` reserves pilot admission
//! budget, the aggregate TVL cap is one 0.2 HAC channel wide, and nothing in
//! the tree could ever move a broadcast-but-unmined open out of a reserving
//! status. So the budget was spent by a transaction that does not exist, the
//! spend was permanent, and `/v1/readiness/mainnet` published
//! `aggregate_tvl_within_limit: true` and `blockers: []` the whole time.
//!
//! These tests live inside the crate rather than in `tests/` because they read
//! the durable status of an operation directly, which is the only way to tell
//! a retirement from a refusal that merely looks like one. Nothing here reaches
//! into the Hub to fake a clock: the retirement rule counts blocks, so the
//! reproduction is produced by the mock fullnode's own chain advancing, exactly
//! as a real chain would.
//!
//! Substituted: the user and Hub identities, and therefore the addresses, the
//! deterministic channel ID and both signatures. The owner's own numbers are
//! not substituted: deposit 20_000_000 zhu, fee 24_100 zhu, balance 0.3 HAC in
//! the owner's node's exact wire shape (no `address` key), reuse version 1, a
//! 300 second envelope, profile `mainnet-bounded-pilot`, payment cap
//! 10_000_000, channel cap 20_000_000, aggregate TVL cap 20_000_000.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering as AtomicOrdering};

use axum::extract::Query;
use axum::routing::{get, post};
use axum::{Json, Router};
use basis::interface::Transaction;
use field::{AddrHac, Address, Amount, ChannelId, Field, Serialize as _, Uint4};
use mint::action::ChannelOpen;
use protocol::action::{ChainAllow, ChainIDList};
use protocol::transaction::TransactionType2;
use serde::Deserialize;
use serde_json::json;
use sys::Account;
use tempfile::TempDir;

use super::*;
use crate::channel_id::derive_channel_id;
use crate::l1_channel::{
    L1_CHANNEL_OPEN_SCHEMA, L1ChannelOpenRequest, request_commitment as l1_request_commitment,
    transaction_commitment,
};
use crate::state::open::OPEN_UNMINED_RETIREMENT_BLOCKS;

const JOURNAL_KEY: &str = "7373737373737373737373737373737373737373737373737373737373737373";
const STATE_KEY: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";

/// The owner's live node, read from its own `/query/capabilities`.
const MAINNET_CHAIN_ID: u32 = 0;
const MAINNET_BLOCK_ONE: &str = "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
const MAINNET_INSTANCE: &str = "5a310ec0f487a37156a182c67778495f66e5c7502f9871829edc790023b123cf";
const MAINNET_HEIGHT: u64 = 777_754;

/// The owner's exact numbers.
const OWNER_DEPOSIT_HAC: &str = "0.2";
const OWNER_DEPOSIT_ZHU: u64 = 20_000_000;
const OWNER_FEE_HAC: &str = "0.000241";
const OWNER_BALANCE_HAC: &str = "0.3";
const OWNER_ENVELOPE_SECONDS: u64 = 300;
const OWNER_MAX_CHANNEL_FUNDING_ZHU: u64 = 20_000_000;
const OWNER_MAX_PAYMENT_ZHU: u64 = 10_000_000;
const OWNER_MAX_AGGREGATE_TVL_ZHU: u64 = 20_000_000;

/// What the mock fullnode says when asked about the prior open's transaction.
/// The retirement turns on exactly this answer, so each value is a test.
const TX_ABSENT: u8 = 0;
const TX_PENDING: u8 = 1;
const TX_UNREACHABLE: u8 = 2;

/// What the mock fullnode says when asked about the prior open's channel.
const CHANNEL_ABSENT: u8 = 0;
const CHANNEL_PRESENT: u8 = 1;

#[derive(Deserialize)]
struct ChannelQuery {
    id: Option<String>,
}

#[derive(Deserialize)]
struct TransactionQuery {
    hash: Option<String>,
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

/// The two knobs a retirement turns on, shared with the running mock node.
#[derive(Clone)]
struct NodeAnswers {
    transaction: Arc<AtomicU8>,
    channel: Arc<AtomicU8>,
    height: Arc<AtomicU64>,
    prior_channel_id: Arc<std::sync::RwLock<String>>,
    /// Exact bytes the node was handed, by transaction hash. A pending answer
    /// has to carry the real body or the Hub's parser rejects it as malformed
    /// and the retirement is refused for the wrong reason - which is exactly
    /// what a first pass at this test did.
    bodies: Arc<std::sync::RwLock<HashMap<String, String>>>,
}

impl NodeAnswers {
    fn new() -> Self {
        Self {
            transaction: Arc::new(AtomicU8::new(TX_ABSENT)),
            channel: Arc::new(AtomicU8::new(CHANNEL_ABSENT)),
            height: Arc::new(AtomicU64::new(MAINNET_HEIGHT)),
            prior_channel_id: Arc::new(std::sync::RwLock::new(String::new())),
            bodies: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Mine `blocks` empty blocks. None of them contains the parked open,
    /// which is the whole evidence a retirement rests on.
    fn mine(&self, blocks: u64) {
        self.height.fetch_add(blocks, AtomicOrdering::AcqRel);
    }
}

/// A mock of the owner's mainnet fullnode. Mainnet chain 0 at the owner's
/// height, the owner's block-1 hash and network instance, a fresh tip, and a
/// balance answered in the owner's node's exact wire shape - a single-entry
/// list with no `address` key, which is the fallback arm the Hub's balance
/// parser lands on for the owner.
async fn spawn_mock_node(answers: NodeAnswers, balance_hac: String) -> (String, TempDir) {
    let channel_answers = answers.clone();
    let transaction_answers = answers.clone();
    let capability_answers = answers.clone();
    let submit_answers = answers.clone();
    let app = Router::new()
        .route(
            "/query/channel",
            get(move |Query(query): Query<ChannelQuery>| {
                let answers = channel_answers.clone();
                async move {
                    let asked = query.id.unwrap_or_default();
                    let prior = answers.prior_channel_id.read().unwrap().clone();
                    let present = answers.channel.load(AtomicOrdering::Acquire) == CHANNEL_PRESENT
                        && !prior.is_empty()
                        && asked.eq_ignore_ascii_case(&prior);
                    if present {
                        // Shaped like a real open channel so that
                        // `exact_open_channel_matches` has something to
                        // compare, and so that the sweep sees a channel rather
                        // than a malformed answer.
                        Json(json!({
                            "ret": 0,
                            "id": asked,
                            "status": "opening",
                            "reuse_version": 1,
                            "open_height": MAINNET_HEIGHT,
                            "close_height": 0,
                            "left": {"address": "", "hacash": fin(OWNER_DEPOSIT_HAC), "satoshi": 0},
                            "right": {"address": "", "hacash": fin("0"), "satoshi": 0}
                        }))
                    } else {
                        Json(json!({"ret": 1, "err": "channel not found"}))
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get(move |Query(query): Query<TransactionQuery>| {
                let answers = transaction_answers.clone();
                async move {
                    let hash = query.hash.unwrap_or_default();
                    let body = answers.bodies.read().unwrap().get(&hash).cloned();
                    match (answers.transaction.load(AtomicOrdering::Acquire), body) {
                        // A well formed pending answer, carrying the exact
                        // bytes the node was handed. Anything less and the
                        // Hub's parser refuses it as malformed, which would
                        // pass this test for the wrong reason.
                        (TX_PENDING, Some(body)) => Json(json!({
                            "ret": 0,
                            "hash": hash,
                            "tx_type": 2,
                            "body": body,
                            "actions": [{"kind": 1041}],
                            "signatures": [{"publickey": "", "signature": ""}],
                            "pending": true
                        })),
                        (TX_UNREACHABLE, _) => {
                            Json(json!({"ret": 1, "err": "fullnode index is rebuilding"}))
                        }
                        _ => Json(json!({"ret": 1, "err": "transaction not found"})),
                    }
                }
            }),
        )
        .route(
            "/query/balance",
            get(move || {
                let balance_hac = balance_hac.clone();
                async move {
                    Json(json!({
                        "ret": 0,
                        "list": [{"diamond": 0, "hacash": balance_hac, "satoshi": 0}]
                    }))
                }
            }),
        )
        .route(
            "/query/capabilities",
            get(move || {
                let answers = capability_answers.clone();
                async move {
                    let now = crate::node::now_unix();
                    let height = answers.height.load(AtomicOrdering::Acquire);
                    Json(json!({
                        "ret": 0,
                        "api_version": 1,
                        "api": { "transaction_submit_bound": true },
                        "chain": {
                            "id": MAINNET_CHAIN_ID,
                            "height": height,
                            "next_height": height + 1,
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
                        "features": { "channel_unilateral_exit": false }
                    }))
                }
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post(move |body: String| {
                let answers = submit_answers.clone();
                async move {
                    // The owner's Aug 25 open reached `l1_open_submitted`: the
                    // node took the broadcast and the channel never appeared.
                    // That is the state this whole file is about.
                    let raw = hex::decode(&body).unwrap();
                    let (tx, _consumed) = protocol::transaction::transaction_create(&raw).unwrap();
                    let hash = hex::encode(tx.hash().as_bytes());
                    answers
                        .bodies
                        .write()
                        .unwrap()
                        .insert(hash.clone(), body.clone());
                    Json(json!({"ret": 0, "hash": hash}))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, tempfile::tempdir().unwrap())
}

/// The owner's request shape with substituted identities, eight seconds into a
/// three hundred second envelope - the owner's own prepare-to-sign gap.
fn owner_shaped_request(user: &Account, hub: &Account) -> L1ChannelOpenRequest {
    crate::protocol_registry::ensure_hacash_protocol_setup();
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
    let created = crate::node::now_unix().saturating_sub(8);
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
        idempotency_key: format!("hpay:channel-open:{}", uuid::Uuid::new_v4()),
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
    let commitment: [u8; 32] = hex::decode(l1_request_commitment(&request).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
    request
}

struct Owner {
    hub: HubState,
    answers: NodeAnswers,
    prior_request: L1ChannelOpenRequest,
    owner_request: L1ChannelOpenRequest,
    _directory: TempDir,
}

/// The owner's Hub, at the owner's flags, carrying nothing yet.
async fn owner_hub() -> Owner {
    let prior_user = account("retirement-prior-user");
    let owner_user = account("retirement-owner-user");
    let hub_account = account("retirement-hub");
    let prior_request = owner_shaped_request(&prior_user, &hub_account);
    let owner_request = owner_shaped_request(&owner_user, &hub_account);
    let answers = NodeAnswers::new();
    *answers.prior_channel_id.write().unwrap() = prior_request.channel_id.clone();
    let (node_url, directory) = spawn_mock_node(answers.clone(), fin(OWNER_BALANCE_HAC)).await;
    let admission = MainnetPilotAdmissionPolicy::try_new(
        [
            prior_user.readable().to_owned(),
            owner_user.readable().to_owned(),
        ],
        OWNER_MAX_AGGREGATE_TVL_ZHU,
    )
    .unwrap();
    let hub = HubState::new_secure_with_mainnet_admission_signer(
        "owner-like bounded pilot hub",
        hub_account.readable(),
        &node_url,
        None,
        directory.path().join("hub-state.json"),
        HubSigner::from_secret_hex(&secret_hex(&hub_account)).unwrap(),
        JOURNAL_KEY,
        STATE_KEY,
        "mainnet-bounded-pilot",
        OWNER_MAX_PAYMENT_ZHU,
        OWNER_MAX_CHANNEL_FUNDING_ZHU,
        admission,
    )
    .unwrap();
    Owner {
        hub,
        answers,
        prior_request,
        owner_request,
        _directory: directory,
    }
}

/// Reproduce the owner's Aug 25 record: one open for a different allowlisted
/// address, driven through the real path until the node takes the broadcast
/// and the channel never appears. Nothing about it is faked - the whole path
/// runs, including the broadcast, and the record it leaves is the owner's:
/// status `Submitted`, no inclusion evidence, holding the entire pilot budget.
async fn park_a_dead_open(owner: &Owner) -> String {
    let response = owner.hub.open_channel(&owner.prior_request).await.unwrap();
    assert_eq!(
        response.status, "submitted",
        "the prior open must land in the owner's Aug 25 status"
    );
    let operation_id = response.operation_id.clone();
    {
        let guard = owner.hub.inner.read().unwrap();
        let operation = guard.l1_channel_opens.get(&operation_id).unwrap();
        assert!(
            operation.confirmed_block_height.is_none() && operation.observed_confirmations == 0,
            "the owner's record carried no inclusion evidence and neither may this one"
        );
        assert_eq!(
            operation.broadcast_height,
            Some(MAINNET_HEIGHT),
            "the height the bytes went on the wire at must be recorded, or nothing can count \
             blocks from it"
        );
    }
    operation_id
}

fn open_status(hub: &HubState, operation_id: &str) -> L1ChannelOpenStatus {
    hub.inner
        .read()
        .unwrap()
        .l1_channel_opens
        .get(operation_id)
        .unwrap()
        .status
        .clone()
}

/// THE FIX. The owner's exact refusal, and then the owner's exact open going
/// through, on one Hub, with nothing changed between them but the chain
/// producing one more block.
#[tokio::test]
async fn the_owner_open_is_refused_while_the_dead_reservation_stands_and_succeeds_once_it_is_released()
 {
    let owner = owner_hub().await;

    let dead = park_a_dead_open(&owner).await;

    // One block short of the retirement floor is the honest worst case, so
    // start there. The owner's own record was five days and roughly 1400
    // blocks past it.
    owner.answers.mine(OPEN_UNMINED_RETIREMENT_BLOCKS - 1);

    let refusal = owner
        .hub
        .open_channel(&owner.owner_request)
        .await
        .expect_err("the owner's open must be refused while the dead reservation stands");
    println!("---- THE REFUSAL, AND WHAT IT NOW SAYS ----");
    println!("{refusal}");
    let refusal = refusal.to_string();
    assert!(
        refusal.contains(
            "mainnet pilot aggregate Hub TVL cap exceeded: proposed 40000000 zhu, cap 20000000 zhu"
        ),
        "the owner's own sentence must still be the first thing said: {refusal}"
    );
    assert!(
        refusal.contains("20000000 zhu of that cap is already held"),
        "the refusal must say the budget is already spent: {refusal}"
    );
    assert!(
        refusal.contains(&dead),
        "the refusal must name the operation holding the budget: {refusal}"
    );
    assert!(
        refusal.contains("status submitted"),
        "the refusal must say what state that operation is in: {refusal}"
    );
    assert_eq!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::Submitted,
        "one block short of the floor retires nothing"
    );

    // One more block, and nothing else changes: the same Hub, the same node
    // answering the same "channel not found" and "transaction not found", the
    // same request.
    owner.answers.mine(1);

    let accepted = owner
        .hub
        .open_channel(&owner.owner_request)
        .await
        .expect("the owner's open must now go through");
    println!("---- THE OPEN THAT NOW HAPPENS ----");
    println!("{accepted:?}");
    assert_eq!(accepted.channel_id, owner.owner_request.channel_id);
    assert_eq!(accepted.operation_id, owner.owner_request.operation_id);
    assert_eq!(
        accepted.status, "submitted",
        "the owner's open must reach the chain, not another refusal"
    );

    assert_eq!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::AbandonedUnmined,
        "the dead open must be retired, not deleted"
    );
    let retired = owner
        .hub
        .inner
        .read()
        .unwrap()
        .l1_channel_opens
        .get(&dead)
        .unwrap()
        .clone();
    println!("---- WHY IT WAS RETIRED ----");
    println!("{}", retired.last_error.clone().unwrap());
    let reason = retired.last_error.as_deref().unwrap();
    assert!(
        reason.contains(&format!(
            "the chain has produced {OPEN_UNMINED_RETIREMENT_BLOCKS} blocks since it was \
             broadcast at height {MAINNET_HEIGHT}"
        )),
        "the retirement must record what evidence it acted on: {reason}"
    );
    assert!(
        reason.contains("the fullnode does not hold it pending either"),
        "the retirement must record that the mempool was asked too: {reason}"
    );
    assert!(
        reason.contains("is taken back at the next channel-open"),
        "the retirement must say it is not final: {reason}"
    );
    assert!(
        retired.signed_transaction_hex.is_some(),
        "the exact bytes must be kept: a retirement gives up the reservation, not the record"
    );
    assert!(
        retired.status.has_durable_signature(),
        "a retired open must keep being watched"
    );
}

/// The Hub must not retire an open whose transaction the fullnode is still
/// holding. That is a transaction between blocks, not a dead one.
#[tokio::test]
async fn a_transaction_the_fullnode_still_holds_pending_keeps_its_budget() {
    let owner = owner_hub().await;
    let dead = park_a_dead_open(&owner).await;
    owner.answers.mine(OPEN_UNMINED_RETIREMENT_BLOCKS * 5);
    owner
        .answers
        .transaction
        .store(TX_PENDING, AtomicOrdering::Release);

    let refusal = owner
        .hub
        .open_channel(&owner.owner_request)
        .await
        .expect_err("a pending transaction must keep holding its budget");
    println!("pending: {refusal}");
    assert!(
        refusal
            .to_string()
            .contains("aggregate Hub TVL cap exceeded")
    );
    assert_eq!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::Submitted
    );
}

/// A fullnode that cannot answer proves nothing. Not knowing is not evidence,
/// and the reservation stands.
#[tokio::test]
async fn a_fullnode_that_cannot_be_asked_retires_nothing() {
    let owner = owner_hub().await;
    let dead = park_a_dead_open(&owner).await;
    owner.answers.mine(OPEN_UNMINED_RETIREMENT_BLOCKS * 5);
    owner
        .answers
        .transaction
        .store(TX_UNREACHABLE, AtomicOrdering::Release);

    let refusal = owner
        .hub
        .open_channel(&owner.owner_request)
        .await
        .expect_err("an unanswerable fullnode must keep the reservation");
    println!("unreachable: {refusal}");
    assert!(
        refusal
            .to_string()
            .contains("aggregate Hub TVL cap exceeded")
    );
    assert_eq!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::Submitted
    );
}

/// The channel exists on chain after all. That is the one answer that must
/// never be read as a retirement, because the deposit is real.
#[tokio::test]
async fn a_channel_that_exists_on_chain_keeps_its_budget() {
    let owner = owner_hub().await;
    let dead = park_a_dead_open(&owner).await;
    owner.answers.mine(OPEN_UNMINED_RETIREMENT_BLOCKS * 5);
    owner
        .answers
        .channel
        .store(CHANNEL_PRESENT, AtomicOrdering::Release);

    let refusal = owner
        .hub
        .open_channel(&owner.owner_request)
        .await
        .expect_err("a channel that exists must keep holding its budget");
    println!("channel present: {refusal}");
    assert!(
        refusal
            .to_string()
            .contains("aggregate Hub TVL cap exceeded")
    );
    assert_ne!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::AbandonedUnmined
    );
}

/// A retired open is watched, not buried. If a channel appears at its ID after
/// all, the very next resume acts on that rather than leaving the Hub a silent
/// party to a channel it has retired. Here the channel that appears does not
/// match the operation, so the Hub latches recovery - which is the same
/// behaviour it has always had for a mismatched incarnation, and the point is
/// that a retirement does not suppress it.
#[tokio::test]
async fn a_retired_open_is_taken_back_when_the_chain_contradicts_the_retirement() {
    let owner = owner_hub().await;
    let dead = park_a_dead_open(&owner).await;
    owner.answers.mine(OPEN_UNMINED_RETIREMENT_BLOCKS * 5);

    owner.hub.open_channel(&owner.owner_request).await.unwrap();
    assert_eq!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::AbandonedUnmined
    );

    // The chain contradicts the retirement.
    owner
        .answers
        .channel
        .store(CHANNEL_PRESENT, AtomicOrdering::Release);
    let resumed = owner
        .hub
        .open_channel(&owner.prior_request)
        .await
        .expect("a retired open must still be resumable");
    println!("re-adopted: {resumed:?}");
    assert_ne!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::AbandonedUnmined,
        "an open whose channel ID the chain now knows must not stay quietly retired"
    );
}

/// A retired open's bytes must never be put back on the wire by the Hub.
#[tokio::test]
async fn a_retired_open_is_never_rebroadcast() {
    let owner = owner_hub().await;
    let dead = park_a_dead_open(&owner).await;
    owner.answers.mine(OPEN_UNMINED_RETIREMENT_BLOCKS * 5);
    owner.hub.open_channel(&owner.owner_request).await.unwrap();
    assert_eq!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::AbandonedUnmined
    );

    let resumed = owner.hub.open_channel(&owner.prior_request).await.unwrap();
    assert_eq!(
        resumed.status, "abandoned_unmined",
        "a resume of a retired open reports the retirement and does nothing else"
    );
    assert_eq!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::AbandonedUnmined,
        "resuming a retired open must not walk it back onto the wire"
    );
}

/// The second half of the defect: a Hub at exactly its cap published itself as
/// completely healthy, because `aggregate_tvl_within_limit` is `current <= cap`
/// and equality is inside the cap.
#[tokio::test]
async fn readiness_says_out_loud_that_a_hub_at_its_cap_admits_nothing() {
    let owner = owner_hub().await;
    park_a_dead_open(&owner).await;
    owner.answers.mine(OPEN_UNMINED_RETIREMENT_BLOCKS * 5);

    let readiness = owner.hub.mainnet_readiness().await;
    println!("---- AT THE CAP ----");
    println!(
        "  payments_enabled               = {}",
        readiness.payments_enabled
    );
    println!(
        "  blockers                       = {:?}",
        readiness.blockers
    );
    println!(
        "  aggregate_tvl_within_limit     = {}",
        readiness.aggregate_tvl_within_limit
    );
    println!(
        "  aggregate_tvl_hac_zhu          = {}",
        readiness.aggregate_tvl_hac_zhu
    );
    println!(
        "  aggregate_tvl_headroom_hac_zhu = {}",
        readiness.aggregate_tvl_headroom_hac_zhu
    );
    println!(
        "  new_channel_admission_available = {}",
        readiness.new_channel_admission_available
    );

    // Unchanged, and correct: nothing is broken, and every existing channel
    // still settles. This is exactly why it could not be the alarm.
    assert!(readiness.payments_enabled);
    assert!(readiness.blockers.is_empty());
    assert!(readiness.aggregate_tvl_within_limit);

    // New, and the thing the owner needed.
    assert_eq!(readiness.aggregate_tvl_hac_zhu, OWNER_DEPOSIT_ZHU);
    assert_eq!(readiness.aggregate_tvl_headroom_hac_zhu, 0);
    assert!(!readiness.new_channel_admission_available);
    let said = readiness
        .limitations
        .iter()
        .find(|line| line.contains("at its aggregate TVL cap"))
        .expect("the document must say in words that no new channel can be admitted");
    println!("  says: {said}");
    assert!(said.contains("20000000 zhu of 20000000 zhu"));
    assert!(said.contains("Existing channels are unaffected"));

    // And after the release, the same endpoint says there is room again.
    owner.hub.open_channel(&owner.owner_request).await.unwrap();
    let readiness = owner.hub.mainnet_readiness().await;
    println!("---- AFTER THE RELEASE ----");
    println!(
        "  aggregate_tvl_hac_zhu          = {}",
        readiness.aggregate_tvl_hac_zhu
    );
    println!(
        "  new_channel_admission_available = {}",
        readiness.new_channel_admission_available
    );
    assert_eq!(
        readiness.aggregate_tvl_hac_zhu, OWNER_DEPOSIT_ZHU,
        "the owner's own open now holds the budget, and only it"
    );
    assert!(!readiness.new_channel_admission_available);
    assert!(
        readiness.aggregate_tvl_within_limit,
        "the Hub is at its cap again, legitimately, because the cap is one channel wide"
    );
}

/// A per-address reservation is released too, so the wallet whose open died is
/// not locked out of its own Hub either.
#[tokio::test]
async fn the_wallet_whose_open_died_can_open_again_itself() {
    let owner = owner_hub().await;
    let dead = park_a_dead_open(&owner).await;
    owner.answers.mine(OPEN_UNMINED_RETIREMENT_BLOCKS * 5);

    // Retire it by way of the other wallet's open, then take that one out of
    // the way so only the per-address rule is left to answer.
    owner.hub.open_channel(&owner.owner_request).await.unwrap();
    assert_eq!(
        open_status(&owner.hub, &dead),
        L1ChannelOpenStatus::AbandonedUnmined
    );
    {
        let mut guard = owner.hub.inner.write().unwrap();
        guard
            .l1_channel_opens
            .remove(&owner.owner_request.operation_id);
    }

    let state = owner.hub.inner.read().unwrap().clone();
    let died_for = state
        .l1_channel_opens
        .get(&dead)
        .unwrap()
        .user_address
        .clone();
    assert!(
        crate::state::open::require_new_open_admission(&state, &died_for).is_ok(),
        "MAX_ACTIVE_OPENS_PER_ADDRESS counts reserving opens, so a retired one must not lock \
         its own wallet out of the Hub for good"
    );
}
