//! THE RETRY THAT NEVER SAID WHY, AND THE SIGNATURE NOBODY WOULD EVER ACCEPT.
//!
//! The owner signed their first mainnet Fast Pay channel open at 10:11:48, the
//! Hub refused it, and the wallet threw the reason away. They pressed the
//! button twice more, got the same blank `recovery_required` twice more, and
//! spent the night with a signed request no Hub would accept and no way to
//! cancel it.
//!
//! Nothing here touches mainnet. The node is the same in-process mock Local
//! Pilot node every other pilot test drives, on chain 7 with `mainnet: false`.
//! The Hub is the real [`l2_fast_pay_hub::HubState`] behind the real
//! [`l2_fast_pay_hub::build_router`], on an ephemeral loopback port.
//!
//! # How the Hub is made to refuse, and why this shape
//!
//! The Hub reads its OWN fullnode, not the wallet's. So it gets its own mock
//! node, identical in every respect except one: it reports the user address as
//! holding almost nothing. `require_open_funding`
//! (`l2_fast_pay_hub::state::require_open_funding`) then refuses with a
//! sentence naming both numbers, and it refuses **every** time, permanently,
//! exactly like the owner's aggregate-TVL refusal did. It is deliberately a
//! refusal that leaves `/v1/health` and the open-readiness gate green, because
//! the owner's did too: a Hub that looks perfectly healthy and admits nothing
//! is the whole shape of the night.
//!
//! The reason the owner's specific refusal (aggregate pilot TVL) is not the one
//! reproduced here is that it is mainnet-profile-only, and this file may never
//! stand up a mainnet-profile anything. The branch being tested in the WALLET
//! is `channel_setup.rs`'s handling of `Err` from `hub.open_channel`, which
//! cannot tell one `HubError` from another.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::l1_channel_safety::{ChannelOpenOperation, ChannelOpenStatus};
use l2_fast_pay_hub::{HubState, build_router};
use serde_json::json;

use super::*;
use crate::service::l2::{AgentChannelSetupOperation, AgentChannelSetupPhase};

/// The deposit the owner-shaped test wallet asks for, and the balance the
/// Hub's own node reports for it. The gap is the refusal.
const DEPOSIT_HAC: &str = "1";
const HUB_SEEN_BALANCE_HAC: &str = "0.0001";

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------------------
// The Hub's own fullnode, which reports the user as unfunded.
// ---------------------------------------------------------------------------

struct HubSideNode {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HubSideNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_hub_side_node(balance_hac: &'static str) -> HubSideNode {
    // The Hub asks for `unit=fin`, so the answer has to be in the node's own
    // finite-mantissa wire form rather than a decimal string.
    let balance_fin = field::Amount::from(balance_hac).unwrap().to_fin_string();
    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async { Json(super::pilot_node::official_capabilities()) }),
        )
        .route(
            "/query/block/intro",
            get(|| async {
                Json(json!({"ret": 0, "height": 1, "hash": fixtures::TESTNET_ANCHOR}))
            }),
        )
        .route(
            "/query/channel",
            get(|| async { Json(json!({"ret": 1, "err": "channel not found"})) }),
        )
        .route(
            "/query/transaction",
            get(|| async { Json(json!({"ret": 1, "err": "transaction not found"})) }),
        )
        // One entry with no address is the older-node single-address shape the
        // Hub's client accepts, so this answers for whichever address is asked
        // about without the test knowing it.
        .route(
            "/query/balance",
            get(move || {
                let balance_fin = balance_fin.clone();
                async move { Json(json!({"ret": 0, "list": [{"hacash": balance_fin}]})) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    HubSideNode { url, task }
}

// ---------------------------------------------------------------------------
// The real Hub, with every POST to the open route counted.
// ---------------------------------------------------------------------------

struct CountedHub {
    url: String,
    address: String,
    opens: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CountedHub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn count_open_posts(
    State(counter): State<Arc<AtomicUsize>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if request.uri().path() == "/v1/l1/channel/open" {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    next.run(request).await
}

async fn spawn_counted_hub(node_url: &str) -> CountedHub {
    let account = WalletAccount::create_random().unwrap();
    let address = account.address();
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "Agent channel-open retry test Hub",
            address.clone(),
            node_url.to_owned(),
            None,
            dir.path().join("hub-state.json"),
            hex::encode(account.inner().secret_key().serialize()),
            &"64".repeat(32),
            &"65".repeat(32),
            "testnet",
            1_000_000_000,
            1_000_000_000,
        )
        .unwrap(),
    );
    let opens = Arc::new(AtomicUsize::new(0));
    let router = build_router(state).layer(axum::middleware::from_fn_with_state(
        opens.clone(),
        count_open_posts,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    CountedHub {
        url,
        address,
        opens,
        _dir: dir,
        task,
    }
}

// ---------------------------------------------------------------------------
// The owner's state, produced by the real path rather than written by hand.
// ---------------------------------------------------------------------------

struct RefusedOpen {
    _root: tempfile::TempDir,
    _node: super::pilot_node::MockPilotNode,
    _hub_node: HubSideNode,
    manager: AgentWalletManager,
    wallet_id: AgentWalletId,
    hub: CountedHub,
    setup: AgentChannelSetupOperation,
    first_refusal: AgentWalletError,
}

fn stored_setup(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
) -> Option<AgentChannelSetupOperation> {
    let (state_master, journal_key) = fixtures::keys(manager, wallet_id);
    manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
        .l2_channel_setup
}

fn durable_operation(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    setup: &AgentChannelSetupOperation,
) -> ChannelOpenOperation {
    let paths = manager.storage.paths(wallet_id).unwrap();
    let signer = &manager.session(wallet_id).unwrap().signer;
    hacash_wallet_core::l1_channel_safety::ChannelOpenSafety::open_scoped(
        signer,
        paths.l2_dir(),
        crate::types::WalletScope::for_agent_wallet(wallet_id).as_str(),
        &setup.review.hub_address,
        &setup.review.channel_id,
        setup.review.channel_reuse_version,
    )
    .unwrap()
    .operation()
    .unwrap()
}

/// Drive the real prepare and the real confirm, and stop where the owner
/// stopped: signed, refused by the Hub, `recovery_required`.
async fn refused_open() -> RefusedOpen {
    let now = unix_now();
    let node = super::pilot_node::spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = super::pilot_node::create_manager_for_node(&node.url, now);
    let hub_node = spawn_hub_side_node(HUB_SEEN_BALANCE_HAC).await;
    let hub = spawn_counted_hub(&hub_node.url).await;

    let review = manager
        .prepare_l2_channel_setup(&wallet_id, &hub.url, DEPOSIT_HAC, unix_now())
        .await
        .expect("prepare the owner-reviewed channel open");
    assert_eq!(review.hub_address, hub.address);
    assert_eq!(review.phase, AgentChannelSetupPhase::Prepared);

    let first_refusal = manager
        .confirm_l2_channel_setup(
            &wallet_id,
            &review.operation_id,
            &review.review_commitment,
            unix_now(),
        )
        .await
        .expect_err("this Hub cannot admit this open and never will");

    let setup = stored_setup(&manager, &wallet_id).expect("the refused setup is still stored");
    RefusedOpen {
        _root: root,
        _node: node,
        _hub_node: hub_node,
        manager,
        wallet_id,
        hub,
        setup,
        first_refusal,
    }
}

// ---------------------------------------------------------------------------
// 1. The owner's durable state, reproduced, and what the retry actually does.
// ---------------------------------------------------------------------------

/// The wallet reaches exactly the state the owner's disk is in, and the
/// journal records exactly the events the owner's journal records.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_open_lands_in_the_owners_exact_durable_state() {
    let fixture = refused_open().await;
    let setup = &fixture.setup;

    assert_eq!(setup.review.phase, AgentChannelSetupPhase::RecoveryRequired);
    assert!(
        setup.signed_request.is_some(),
        "the wallet signed before the Hub refused, exactly as the owner's did"
    );
    assert!(setup.transaction_hash.is_none());

    let durable = durable_operation(&fixture.manager, &fixture.wallet_id, setup);
    println!("---- THE OWNER'S DURABLE STORE, REPRODUCED ----");
    println!("  status                = {:?}", durable.status);
    println!(
        "  request               = {}",
        if durable.request.is_some() {
            "PRESENT"
        } else {
            "ABSENT"
        }
    );
    println!(
        "  response              = {}",
        if durable.response.is_some() {
            "PRESENT"
        } else {
            "ABSENT"
        }
    );
    println!(
        "  node_transaction_hash = {:?}",
        durable.node_transaction_hash
    );
    assert_eq!(durable.status, ChannelOpenStatus::RecoveryRequired);
    assert!(durable.request.is_some());
    assert!(durable.response.is_none());
    assert!(durable.node_transaction_hash.is_none());

    assert_eq!(
        fixture.hub.opens.load(Ordering::SeqCst),
        1,
        "the first confirm reached the Hub exactly once"
    );
}

/// THE DISCRIMINATOR FOR DEFECT B.
///
/// The brief's hypothesis was that the retries fail at
/// `channel_setup.rs`'s `setup.signed_request.as_ref() != Some(&request)`
/// comparison and never reach the Hub. They do reach it. This counts the POSTs
/// on the Hub's own socket, which no amount of reasoning about the comparison
/// can argue with.
#[tokio::test(flavor = "multi_thread")]
async fn every_retry_reaches_the_hub_and_the_stored_request_comparison_is_never_the_refusal() {
    let mut fixture = refused_open().await;
    assert_eq!(fixture.hub.opens.load(Ordering::SeqCst), 1);

    for attempt in 2..=3 {
        let error = fixture
            .manager
            .recover_l2_channel_setup(&fixture.wallet_id, unix_now())
            .await
            .expect_err("the Hub's refusal is permanent");
        println!("retry {attempt} -> {error}");
        assert_eq!(
            fixture.hub.opens.load(Ordering::SeqCst),
            attempt,
            "retry {attempt} did not reach the Hub, so something before the POST refused it"
        );
    }

    // The durable request survives every round trip byte for byte, which is
    // why the comparison the brief suspected can never fail here.
    let durable = durable_operation(&fixture.manager, &fixture.wallet_id, &fixture.setup);
    assert_eq!(
        durable.request.as_ref(),
        fixture.setup.signed_request.as_ref(),
        "the durable request and the wallet-state request are the same bytes"
    );
    assert_eq!(durable.status, ChannelOpenStatus::RecoveryRequired);
    assert!(durable.response.is_none());
}

// ---------------------------------------------------------------------------
// 2. The reason.
// ---------------------------------------------------------------------------

/// The Hub's own sentence reaches the caller, and it is the sentence that
/// names both numbers.
#[tokio::test(flavor = "multi_thread")]
async fn the_hubs_refusal_reaches_the_caller_word_for_word() {
    let fixture = refused_open().await;
    let text = fixture.first_refusal.to_string();
    println!("---- WHAT THE OWNER IS TOLD ----\n{text}");
    assert!(
        matches!(
            fixture.first_refusal,
            AgentWalletError::ChannelSetupHubRefused(_)
        ),
        "a blank RecoveryRequired is the defect; got {:?}",
        fixture.first_refusal
    );
    assert!(
        text.contains("channel-open requires") && text.contains("zhu"),
        "the Hub's own words did not survive: {text}"
    );
}

/// And it survives the process, because a toast does not. The owner refreshed
/// the panel; whatever the call returned was gone by then.
#[tokio::test(flavor = "multi_thread")]
async fn the_refusal_is_kept_on_the_stored_setup_so_the_panel_can_show_it_later() {
    let fixture = refused_open().await;
    let stored = stored_setup(&fixture.manager, &fixture.wallet_id).unwrap();
    let kept = stored
        .review
        .last_hub_refusal
        .as_deref()
        .expect("the stored setup remembers why the Hub refused");
    println!("---- WHAT THE PANEL READS AFTER A REFRESH ----\n{kept}");
    assert!(kept.contains("channel-open requires"));
    // Rewriting the reason must not invalidate the review the owner approved.
    stored
        .validate(&fixture.wallet_id, &{
            let (state_master, journal_key) = fixtures::keys(&fixture.manager, &fixture.wallet_id);
            fixture
                .manager
                .load_verified_state(&fixture.wallet_id, &state_master, &journal_key)
                .unwrap()
                .address
        })
        .expect("the stored review still validates with the reason attached");
}

// ---------------------------------------------------------------------------
// 3. The way out of a dead envelope.
// ---------------------------------------------------------------------------

/// Before the envelope closes there is no exit, because there is still a
/// chance the Hub will accept. Abandoning a live request is how a wallet
/// forgets a signature that could still be used.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_signed_request_cannot_be_abandoned() {
    let mut fixture = refused_open().await;
    let error = fixture
        .manager
        .abandon_dead_l2_channel_setup(
            &fixture.wallet_id,
            &fixture.setup.review.operation_id,
            &fixture.setup.review.review_commitment,
            unix_now(),
        )
        .await
        .expect_err("the envelope is still open");
    println!("live envelope -> {error}");
    assert_eq!(error, AgentWalletError::ChannelSetupNotDiscardable);
    assert!(stored_setup(&fixture.manager, &fixture.wallet_id).is_some());
}

/// And not in the gap either.
///
/// One second after the envelope closes, the Hub will not cosign the request,
/// but the transaction itself is only about 300 seconds old and every Hub's
/// transaction-age rule still admits it. The durable store's own guard stops
/// at the envelope, so this second bar is the manager's alone and this is the
/// test that holds it there.
#[tokio::test(flavor = "multi_thread")]
async fn the_gap_between_a_closed_envelope_and_a_stale_transaction_is_not_an_exit() {
    let mut fixture = refused_open().await;
    let just_expired = fixture.setup.review.expires_at + 1;
    fixture
        .manager
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, just_expired)
        .unwrap();
    let error = fixture
        .manager
        .abandon_dead_l2_channel_setup(
            &fixture.wallet_id,
            &fixture.setup.review.operation_id,
            &fixture.setup.review.review_commitment,
            just_expired,
        )
        .await
        .expect_err("the transaction is not old enough yet");
    println!("envelope closed, transaction still young -> {error}");
    assert_eq!(error, AgentWalletError::ChannelSetupNotDiscardable);
    assert!(stored_setup(&fixture.manager, &fixture.wallet_id).is_some());
}

/// Once the envelope and the transaction's own maximum age have both passed,
/// and the store proves nothing came back from the Hub, and the chain proves
/// the channel does not exist, the owner gets out.
#[tokio::test(flavor = "multi_thread")]
async fn a_dead_signed_request_can_be_abandoned_and_the_wallet_can_open_again() {
    let mut fixture = refused_open().await;
    let dead = fixture.setup.review.expires_at + crate::service::l2::CHANNEL_OPEN_DEAD_AFTER;
    // Fifteen minutes later. The owner comes back and unlocks, which is what
    // the panel makes them do too.
    fixture
        .manager
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, dead)
        .unwrap();

    let review = fixture
        .manager
        .abandon_dead_l2_channel_setup(
            &fixture.wallet_id,
            &fixture.setup.review.operation_id,
            &fixture.setup.review.review_commitment,
            dead,
        )
        .await
        .expect("a dead request with nothing behind it has an exit");
    assert_eq!(review.operation_id, fixture.setup.review.operation_id);
    assert!(
        stored_setup(&fixture.manager, &fixture.wallet_id).is_none(),
        "the dead setup is gone"
    );

    let durable = durable_operation(&fixture.manager, &fixture.wallet_id, &fixture.setup);
    assert_eq!(durable.status, ChannelOpenStatus::AbandonedDeadRequest);
    assert!(
        durable.request.is_some(),
        "the signature is not forgotten, only retired"
    );

    // The whole point: the owner can set the channel up again. Same
    // deterministic channel ID, same durable store directory.
    fixture
        .manager
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, unix_now())
        .unwrap();
    let again = fixture
        .manager
        .prepare_l2_channel_setup(
            &fixture.wallet_id,
            &fixture.hub.url,
            DEPOSIT_HAC,
            unix_now(),
        )
        .await
        .expect("prepare works again after the dead request is retired");
    assert_ne!(again.operation_id, fixture.setup.review.operation_id);
    assert_eq!(again.channel_id, fixture.setup.review.channel_id);
    println!(
        "re-prepared {} on channel {}",
        again.operation_id, again.channel_id
    );

    // Preparing again proves nothing on its own: prepare never opens the
    // durable store. Confirming does, and if the retired operation still
    // blocked that store the confirm would refuse before it signed anything
    // and the Hub would never hear from it. So the Hub's own socket is the
    // witness again.
    let before = fixture.hub.opens.load(Ordering::SeqCst);
    let error = fixture
        .manager
        .confirm_l2_channel_setup(
            &fixture.wallet_id,
            &again.operation_id,
            &again.review_commitment,
            unix_now(),
        )
        .await
        .expect_err("this Hub still cannot admit this open");
    println!("re-confirmed -> {error}");
    assert_eq!(
        fixture.hub.opens.load(Ordering::SeqCst),
        before + 1,
        "the retired store blocked the fresh open before it reached the Hub"
    );
    let durable = durable_operation(&fixture.manager, &fixture.wallet_id, &fixture.setup);
    assert_eq!(durable.operation_id, again.operation_id);
    assert_eq!(durable.status, ChannelOpenStatus::RecoveryRequired);
}

/// THE TRAP, PINNED SO NOBODY WIDENS THE WRONG DOOR.
///
/// The two controls that already existed cannot clear this state, and both of
/// them are right to refuse. The discard's whole claim is that no signature
/// was ever produced, and recovery just re-runs the confirm that refused. If a
/// later change makes either of them accept a dead signed setup, this fails,
/// and it should: forgetting a signature through the unsigned door is how a
/// wallet funds the same channel twice.
#[tokio::test(flavor = "multi_thread")]
async fn neither_the_discard_nor_the_recovery_can_clear_a_dead_signed_setup() {
    let mut fixture = refused_open().await;
    let dead = fixture.setup.review.expires_at + crate::service::l2::CHANNEL_OPEN_DEAD_AFTER;
    fixture
        .manager
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, dead)
        .unwrap();

    assert_eq!(
        fixture.manager.discard_unsigned_l2_channel_setup(
            &fixture.wallet_id,
            &fixture.setup.review.operation_id,
            &fixture.setup.review.review_commitment,
            dead,
        ),
        Err(AgentWalletError::ChannelSetupNotDiscardable),
        "the unsigned discard must never accept a setup a signature exists for"
    );

    let before = fixture.hub.opens.load(Ordering::SeqCst);
    let error = fixture
        .manager
        .recover_l2_channel_setup(&fixture.wallet_id, dead)
        .await
        .expect_err("a dead envelope cannot be recovered");
    println!("recover on a dead envelope -> {error}");
    assert!(
        stored_setup(&fixture.manager, &fixture.wallet_id).is_some(),
        "recovery leaves the setup exactly where it was"
    );
    // And it is worse than a refusal. Recovery does not notice the dead
    // envelope at all: it walks straight past the expiry gate, because that
    // gate only fires while `signed_request` is None, and posts the same dead
    // bytes to the Hub again. Against a Hub on the real clock those bytes are
    // refused for expiry rather than for whatever refused them the first time,
    // so the owner is told a second, different, equally unactionable thing.
    // The counter is the proof: pressing the button forever is a network call
    // forever, and never an exit.
    assert_eq!(
        fixture.hub.opens.load(Ordering::SeqCst),
        before + 1,
        "recovery re-posts the dead request rather than stopping"
    );
}

/// The chain is asked, and its answer is allowed to refuse. A node that says
/// the channel exists means the signature DID reach the chain, and no store
/// reading proves otherwise.
#[tokio::test(flavor = "multi_thread")]
async fn a_channel_the_chain_already_knows_about_is_never_abandoned() {
    let mut fixture = refused_open().await;
    let channel_id = fixture.setup.review.channel_id.clone();
    fixture
        ._node
        .set_channel(
            channel_id.clone(),
            json!({
                "ret": 0,
                "id": channel_id,
                "status": 1,
                "open_height": 120,
                "close_height": 0,
                "reuse_version": 1,
                "arbitration_lock": 5000,
                "left": {"address": "1AVRUYpPQqzkYQeUKcdvCJXaXeXCPDT4LG", "hacash": "1", "satoshi": 0},
                "right": {"address": fixture.hub.address, "hacash": "0", "satoshi": 0}
            }),
        )
        .await;
    let dead = fixture.setup.review.expires_at + crate::service::l2::CHANNEL_OPEN_DEAD_AFTER;
    fixture
        .manager
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, dead)
        .unwrap();
    let error = fixture
        .manager
        .abandon_dead_l2_channel_setup(
            &fixture.wallet_id,
            &fixture.setup.review.operation_id,
            &fixture.setup.review.review_commitment,
            dead,
        )
        .await
        .expect_err("the chain says this channel exists");
    println!("channel on chain -> {error}");
    assert_eq!(error, AgentWalletError::ChannelSetupNotDiscardable);
    assert!(stored_setup(&fixture.manager, &fixture.wallet_id).is_some());
}

/// A store that came back from the Hub is not abandonable, whatever the clock
/// says. This is the branch that keeps a submitted open from being forgotten.
#[tokio::test(flavor = "multi_thread")]
async fn a_store_holding_a_hub_response_is_never_abandoned() {
    let mut fixture = refused_open().await;
    {
        let paths = fixture.manager.storage.paths(&fixture.wallet_id).unwrap();
        let signer = &fixture.manager.session(&fixture.wallet_id).unwrap().signer;
        let mut safety = hacash_wallet_core::l1_channel_safety::ChannelOpenSafety::open_scoped(
            signer,
            paths.l2_dir(),
            crate::types::WalletScope::for_agent_wallet(&fixture.wallet_id).as_str(),
            &fixture.setup.review.hub_address,
            &fixture.setup.review.channel_id,
            fixture.setup.review.channel_reuse_version,
        )
        .unwrap();
        let request = fixture.setup.signed_request.clone().unwrap();
        let response = l2_fast_pay_hub::l1_channel::L1ChannelOpenStatusResponse {
            schema: l2_fast_pay_hub::l1_channel::L1_CHANNEL_OPEN_SCHEMA.to_owned(),
            operation_id: request.operation_id.clone(),
            channel_id: request.channel_id.clone(),
            // "recovery_required" and not "submitted" on purpose. A
            // "submitted" answer moves the store to `NodeSubmitted`, which the
            // status gate refuses on its own and which would make this test
            // pass whether or not the response was ever looked at. This answer
            // leaves the store in `RecoveryRequired`, a status a retirement
            // does accept, so the only thing refusing here is the evidence.
            status: "recovery_required".to_owned(),
            transaction_hash: Some("ab".repeat(32)),
        };
        let stored = safety.persist_hub_status(&response).unwrap();
        assert_eq!(
            stored.status,
            hacash_wallet_core::l1_channel_safety::ChannelOpenStatus::RecoveryRequired
        );
    }
    let dead = fixture.setup.review.expires_at + crate::service::l2::CHANNEL_OPEN_DEAD_AFTER;
    fixture
        .manager
        .unlock(&fixture.wallet_id, fixtures::PASSPHRASE, dead)
        .unwrap();
    let error = fixture
        .manager
        .abandon_dead_l2_channel_setup(
            &fixture.wallet_id,
            &fixture.setup.review.operation_id,
            &fixture.setup.review.review_commitment,
            dead,
        )
        .await
        .expect_err("the Hub answered, so this open is not provably nowhere");
    println!("hub response present -> {error}");
    assert_eq!(error, AgentWalletError::ChannelSetupNotDiscardable);
}
