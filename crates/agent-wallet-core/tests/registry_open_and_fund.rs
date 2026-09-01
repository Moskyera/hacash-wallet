//! A REAL AGENT WALLET OPENS A REGISTRY CHANNEL, PAYS INTO IT, AND CANNOT DO
//! EITHER WITHOUT ALREADY HOLDING THE WAY OUT AND HAVING CHECKED THE CHAIN.
//!
//! # What this file is, and what it replaced
//!
//! It is the manager-level suite for the wallet half of the shared registry V2
//! channel open, and it is the successor to four files: the original
//! behavioural suite (`registry_channel_open.rs`) and three adversarial review
//! files (`registry_open_attacks.rs`, `trap_the_user_at_open.rs`,
//! `trap_the_user_on_chain.rs`). Those four were written against a gate that
//! did not read a chain, and their central assertions were that attacks
//! *succeeded*. Every finding they recorded is carried forward here or in one
//! of the two on-chain proofs named below; nothing was dropped to make a suite
//! go green.
//!
//! | reviewer finding | where it is proven now |
//! |---|---|
//! | poisoned contract address, honest Hub, deposit taken | `crates/wallet-core/tests/registry_open_attack_on_chain.rs` (on chain) and `a_channel_whose_contract_this_wallets_node_does_not_corroborate_opens_nothing` below |
//! | channel on a chain the wallet is not pinned to | `a_channel_on_a_chain_this_wallet_is_not_pinned_to_opens_nothing` |
//! | on-chain channel terms differ from the signed binding | `hacash_wallet_core::hvm_registry_open` unit tests, and the node double here refuses to corroborate them |
//! | provider vanishes after funding, owner trapped | `agent_wallet_core::service::hvm_registry::exit_on_chain_tests::a_wallet_opens_pays_and_walks_out_with_the_provider_deleted` |
//! | crash between funding and adoption leaves no record | `a_crash_between_the_deposit_and_its_confirmation_never_signs_a_second_transfer` |
//! | ordinary payment path funds a channel with no refund | `hacash_wallet_core::address` unit test, both agent doors |
//! | worthless countersignature, refusing Hub, crash before funding | kept below, unchanged in substance |
//!
//! # What the Hub here is
//!
//! A deliberately minimal server speaking the two routes the open needs, which
//! can be told to refuse, to sign with a key that is not the bound Hub's, or to
//! sign the right shape of bill for a different incarnation of the channel.
//!
//! # What the node here is
//!
//! `common::HonestNode`: a node that corroborates exactly one channel and tells
//! the truth about everything else. It is not a way of making the gate pass; it
//! is the thing the gate judges.
//!
//! Nothing is broadcast, deployed or spent.

#![cfg(feature = "agent-wallet-testnet-pilot")]

mod common;

use std::sync::Arc;

use agent_wallet_core::{AgentWalletError, AgentWalletId, AgentWalletManager, CreateAgentWallet};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::{HonestNode, NODE_BLOCK_ONE, pilot_network};
use field::{Serialize as _, Sign};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HvmRegistryBillV2, HvmRegistryBindingV2,
    HvmRegistryRefundCountersignRequestV2,
};
use l2_fast_pay_hub::hvm_registry_ledger::{
    HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA, HvmRegistryRefundCountersignResponseV2,
};
use sys::Account;

const PASSPHRASE: &str = "agent wallet passphrase 123";
const DEPOSIT_ZHU: u64 = 5_000_000_000;
const CHALLENGE_BLOCKS: u64 = 12;
const CHANNEL_ID: &str = "6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f";

// ---------------------------------------------------------------------------
// A Hub, honest or otherwise.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum HubBehaviour {
    /// Countersigns exactly what it was asked to countersign.
    Honest,
    /// Answers the open with an HTTP error. A provider is entitled to do this
    /// and the only correct consequence is that no channel opens.
    Refuse,
    /// Returns a perfectly well-formed 97 bytes, signed by a key that is not
    /// the Hub this binding names.
    ImpostorKey,
    /// Returns a signature over the same shape of bill on a *different*
    /// incarnation of the channel: same parties, same deposit, one higher
    /// reuse version. On chain that bill is worthless.
    WrongChannel,
}

#[derive(Clone)]
struct MockHub {
    hub: Arc<Account>,
    impostor: Arc<Account>,
    behaviour: HubBehaviour,
}

async fn health(State(state): State<MockHub>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "version": 7,
        "name": "registry-open-mock",
        "hub_address": state.hub.readable(),
        "settlement_ready": true,
        "cross_channel_ready": true,
    }))
}

async fn open_countersign(
    State(state): State<MockHub>,
    Json(request): Json<HvmRegistryRefundCountersignRequestV2>,
) -> Result<Json<HvmRegistryRefundCountersignResponseV2>, axum::http::StatusCode> {
    request
        .validate_shape()
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    if state.behaviour == HubBehaviour::Refuse {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }
    let hash = match state.behaviour {
        HubBehaviour::WrongChannel => {
            let mut other = request.binding.clone();
            other.reuse_version += 1;
            let bill = HvmRegistryBillV2 {
                schema: HVM_REGISTRY_BILL_SCHEMA.into(),
                binding_commitment: other.commitment().expect("other binding commits"),
                serial: 1,
                left_balance_zhu: other.left_deposit_zhu,
                hub_balance_zhu: 0,
                left_signature_hex: String::new(),
                hub_signature_hex: String::new(),
            };
            bill.signing_hash(&other).expect("other bill hashes")
        }
        _ => request
            .left_signed_refund_bill
            .signing_hash(&request.binding)
            .expect("asked bill hashes"),
    };
    let signer: &Account = match state.behaviour {
        HubBehaviour::ImpostorKey => state.impostor.as_ref(),
        _ => state.hub.as_ref(),
    };
    Ok(Json(HvmRegistryRefundCountersignResponseV2 {
        schema: HVM_REGISTRY_REFUND_COUNTERSIGN_RESPONSE_SCHEMA.into(),
        hub_refund_signature_hex: hex::encode(Sign::create_by(signer, &hash).serialize()),
        anchor_receipts: Vec::new(),
    }))
}

async fn spawn_hub(
    hub: Arc<Account>,
    behaviour: HubBehaviour,
) -> (String, tokio::task::JoinHandle<()>) {
    let state = MockHub {
        hub,
        impostor: Arc::new(account("registry-open-impostor")),
        behaviour,
    };
    let router = Router::new()
        .route("/v1/health", get(health))
        .route(
            "/v2/hvm-registry/channel/open-countersign",
            post(open_countersign),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{address}"), handle)
}

// ---------------------------------------------------------------------------
// The wallet, and the channel it wants.
// ---------------------------------------------------------------------------

fn account(seed: &str) -> Account {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    Account::create_by(seed).unwrap()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The channel description a provider publishes and an owner hands in.
fn binding(left_address: &str, hub: &Account) -> HvmRegistryBindingV2 {
    let network = pilot_network();
    let contract = vm::ContractAddress::from_unchecked(field::Address::create_contract([21; 20]))
        .to_readable();
    HvmRegistryBindingV2 {
        schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: network.chain_id,
        network_instance_id: network.network_instance_id.clone(),
        contract_address: contract,
        deployment_tx_hash: "5e".repeat(32),
        deployment_height: 64,
        bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: CHANNEL_ID.into(),
        reuse_version: 0,
        left_address: left_address.to_owned(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: CHALLENGE_BLOCKS,
    }
}

struct Wallet {
    manager: AgentWalletManager,
    wallet_id: AgentWalletId,
    address: String,
    root: tempfile::TempDir,
}

fn open_wallet() -> Wallet {
    let root = tempfile::tempdir().unwrap();
    let manager = AgentWalletManager::open(root.path()).unwrap();
    finish_wallet(root, manager)
}

fn finish_wallet(root: tempfile::TempDir, mut manager: AgentWalletManager) -> Wallet {
    let now = now_unix();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.into(),
                network_mode: "testnet".into(),
                node_url: "http://127.0.0.1:18081".into(),
                block_one_fingerprint: Some(NODE_BLOCK_ONE.into()),
                mainnet_pilot_acknowledgement: None,
            },
            now,
        )
        .unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, now).unwrap();
    Wallet {
        manager,
        wallet_id: created.wallet_id,
        address: created.address,
        root,
    }
}

// ---------------------------------------------------------------------------
// The ordering: nothing, then an ask, then a validated refund, then permission.
// ---------------------------------------------------------------------------

/// The whole sequence in one pass, with a node that corroborates the channel.
#[tokio::test]
async fn funding_is_refused_until_the_hub_countersigns_the_full_refund() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let wanted = binding(&wallet.address, &hub);
    let node = HonestNode::for_channel(&wanted);

    // 1. A fresh wallet has no way in and says so.
    assert!(
        matches!(
            wallet
                .manager
                .hvm_registry_funding_authorization(&wallet.wallet_id, &node, now)
                .await,
            Err(AgentWalletError::RegistryOpenRefundNotCountersigned)
        ),
        "a wallet that has opened nothing must refuse to fund anything"
    );

    // 2. The wallet's own left signature, alone, authorises nothing. This is
    //    the half-signed state a crash between the ask and the answer leaves.
    let ask = wallet
        .manager
        .begin_hvm_registry_channel_open(&wallet.wallet_id, &hub_url, wanted.clone(), &node, now)
        .await
        .expect("the wallet left-signs its own serial-1 full refund");
    assert_eq!(ask.left_signed_refund_bill.serial, 1);
    assert_eq!(ask.left_signed_refund_bill.left_balance_zhu, DEPOSIT_ZHU);
    assert_eq!(ask.left_signed_refund_bill.hub_balance_zhu, 0);
    assert!(ask.left_signed_refund_bill.hub_signature_hex.is_empty());
    assert!(
        matches!(
            wallet
                .manager
                .hvm_registry_funding_authorization(&wallet.wallet_id, &node, now)
                .await,
            Err(AgentWalletError::RegistryOpenRefundNotCountersigned)
        ),
        "half a signature is not a refund"
    );

    // 3. Asking again for the same channel returns the stored ask rather than
    //    minting a second serial-1 bill.
    let again = wallet
        .manager
        .begin_hvm_registry_channel_open(&wallet.wallet_id, &hub_url, wanted.clone(), &node, now)
        .await
        .expect("a repeat ask is the stored ask");
    assert_eq!(again, ask);

    // 4. The provider countersigns, the wallet judges it, and only now does
    //    the gate open.
    let bundle = wallet
        .manager
        .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, wanted.clone(), &node, now)
        .await
        .expect("an honest provider countersigns the full refund");
    assert_eq!(bundle.initial_recovery_bill.left_balance_zhu, DEPOSIT_ZHU);
    let authorization = wallet
        .manager
        .hvm_registry_funding_authorization(&wallet.wallet_id, &node, now)
        .await
        .expect("a validated full refund authorises funding");
    assert_eq!(authorization.amount_zhu(), DEPOSIT_ZHU);
    assert_eq!(
        authorization.contract_address(),
        wanted.contract_address,
        "the deposit goes to the contract in the binding the refund is signed over"
    );
    server.abort();
}

/// A provider that will not countersign opens no channel and costs nothing.
#[tokio::test]
async fn a_hub_that_refuses_to_countersign_opens_no_channel_and_funds_nothing() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Refuse).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let wanted = binding(&wallet.address, &hub);
    let node = HonestNode::for_channel(&wanted);

    let refusal = wallet
        .manager
        .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, wanted, &node, now)
        .await
        .expect_err("a refusing provider opens nothing");
    assert!(matches!(refusal, AgentWalletError::RegistryOpenHubRefused));
    assert!(
        refusal
            .to_string()
            .contains("Nothing was funded and nothing was spent"),
        "the owner must be told plainly: {refusal}"
    );
    assert!(
        matches!(
            wallet
                .manager
                .hvm_registry_funding_authorization(&wallet.wallet_id, &node, now)
                .await,
            Err(AgentWalletError::RegistryOpenRefundNotCountersigned)
        ),
        "the gate is still shut"
    );
    let record = wallet
        .manager
        .hvm_registry_channel_open(&wallet.wallet_id, now)
        .unwrap()
        .expect("the ask is durable");
    assert!(record.countersigned_bundle().is_none());
    assert!(record.funding().is_none(), "nothing was funded");
    server.abort();
}

/// A well-formed answer that is worthless is refused by the wallet, not
/// accepted on trust.
#[tokio::test]
async fn a_worthless_countersignature_is_refused_by_the_wallet() {
    for behaviour in [HubBehaviour::ImpostorKey, HubBehaviour::WrongChannel] {
        let hub = Arc::new(account("registry-open-hub"));
        let (hub_url, server) = spawn_hub(Arc::clone(&hub), behaviour).await;
        let mut wallet = open_wallet();
        let now = now_unix();
        let wanted = binding(&wallet.address, &hub);
        let node = HonestNode::for_channel(&wanted);

        let refusal = wallet
            .manager
            .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, wanted, &node, now)
            .await
            .expect_err("a worthless countersignature opens nothing");
        assert!(matches!(refusal, AgentWalletError::RegistryOpenHubRefused));
        assert!(
            matches!(
                wallet
                    .manager
                    .hvm_registry_funding_authorization(&wallet.wallet_id, &node, now)
                    .await,
                Err(AgentWalletError::RegistryOpenRefundNotCountersigned)
            ),
            "a worthless answer must not reach the gate"
        );
        server.abort();
    }
}

// ---------------------------------------------------------------------------
// THE HOLE THE REVIEWERS DROVE: the binding is a claim, and the wallet now
// checks it against its own node before it signs anything.
// ---------------------------------------------------------------------------

/// A poisoned channel description naming a contract the wallet's own node
/// knows nothing about opens nothing, and no signature is spent finding out.
///
/// This is the attack a reviewer drove to a real theft in real blocks: the Hub
/// is entirely honest and countersigns any well-formed ask that names it, so
/// no hostile provider was ever needed. A pasted JSON blob was enough.
#[tokio::test]
async fn a_channel_whose_contract_this_wallets_node_does_not_corroborate_opens_nothing() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let real = binding(&wallet.address, &hub);
    let node = HonestNode::for_channel(&real);

    let thiefs_contract =
        vm::ContractAddress::from_unchecked(field::Address::create_contract([66; 20]))
            .to_readable();
    let mut poisoned = real.clone();
    poisoned.contract_address = thiefs_contract.clone();
    poisoned
        .validate()
        .expect("it is a perfectly well-formed reviewed-profile binding");

    let refusal = wallet
        .manager
        .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, poisoned, &node, now)
        .await
        .expect_err("the wallet must refuse a contract its own node cannot corroborate");
    assert!(
        matches!(refusal, AgentWalletError::RegistryOpenChainMismatch),
        "unexpected refusal: {refusal}"
    );
    assert!(
        wallet
            .manager
            .hvm_registry_channel_open(&wallet.wallet_id, now)
            .unwrap()
            .is_none(),
        "no signature was spent, and nothing was stored"
    );
    assert!(
        matches!(
            wallet
                .manager
                .hvm_registry_funding_authorization(&wallet.wallet_id, &node, now)
                .await,
            Err(AgentWalletError::RegistryOpenRefundNotCountersigned)
        ),
        "and no permission was manufactured"
    );
    server.abort();
}

/// A refund enforceable only on a chain this wallet is not on is not a refund.
#[tokio::test]
async fn a_channel_on_a_chain_this_wallet_is_not_pinned_to_opens_nothing() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let real = binding(&wallet.address, &hub);
    let node = HonestNode::for_channel(&real);

    for mutate in [
        (|b: &mut HvmRegistryBindingV2| b.chain_id = 4242) as fn(&mut HvmRegistryBindingV2),
        |b: &mut HvmRegistryBindingV2| b.network_instance_id = "de".repeat(32),
    ] {
        let mut foreign = real.clone();
        mutate(&mut foreign);
        foreign
            .validate()
            .expect("still a well-formed reviewed-profile binding");
        let refusal = wallet
            .manager
            .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, foreign, &node, now)
            .await
            .expect_err("a channel on another chain must open nothing");
        assert!(
            matches!(refusal, AgentWalletError::RegistryOpenChainMismatch),
            "unexpected refusal: {refusal}"
        );
        assert!(
            wallet
                .manager
                .hvm_registry_channel_open(&wallet.wallet_id, now)
                .unwrap()
                .is_none()
        );
    }
    server.abort();
}

/// A provider whose published identity is not the one the channel names signs
/// nothing, and costs no signature.
#[tokio::test]
async fn a_provider_whose_published_identity_is_not_the_one_the_channel_names_signs_nothing() {
    let real_hub = Arc::new(account("registry-open-hub"));
    let other_hub = account("registry-open-other-hub");
    let (hub_url, server) = spawn_hub(Arc::clone(&real_hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let wanted = binding(&wallet.address, &other_hub);
    let node = HonestNode::for_channel(&wanted);

    let refusal = wallet
        .manager
        .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, wanted, &node, now)
        .await
        .expect_err("a provider that is not the one this channel names opens nothing");
    assert!(matches!(refusal, AgentWalletError::RegistryOpenHubRefused));
    assert!(
        wallet
            .manager
            .hvm_registry_channel_open(&wallet.wallet_id, now)
            .unwrap()
            .is_none(),
        "no signature was spent finding that out"
    );
    server.abort();
}

/// A node that is merely unreachable opens nothing and stores nothing. Refusing
/// is the safe direction: the alternative is signing on the strength of a
/// document the counterparty wrote.
#[tokio::test]
async fn an_unreachable_node_opens_nothing() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let wanted = binding(&wallet.address, &hub);
    let node = HonestNode::for_channel(&wanted);
    *node.offline.borrow_mut() = true;

    assert!(
        wallet
            .manager
            .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, wanted, &node, now)
            .await
            .is_err()
    );
    assert!(
        wallet
            .manager
            .hvm_registry_channel_open(&wallet.wallet_id, now)
            .unwrap()
            .is_none()
    );
    server.abort();
}

// ---------------------------------------------------------------------------
// Durability, in both windows.
// ---------------------------------------------------------------------------

/// A crash between the countersignature and the funding leaves a refund that
/// is still valid, still reusable, and still authorises exactly the deposit.
#[tokio::test]
async fn a_crash_between_countersign_and_funding_leaves_the_bundle_valid_and_reusable() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let wanted = binding(&wallet.address, &hub);
    let node = HonestNode::for_channel(&wanted);
    let bundle = wallet
        .manager
        .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, wanted.clone(), &node, now)
        .await
        .expect("an honest open");

    // The provider dies and the process does too.
    server.abort();
    let Wallet {
        manager,
        wallet_id,
        address,
        root,
    } = wallet;
    drop(manager);

    // A day later, on a different manager, with no provider anywhere.
    let later = now + 86_400;
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, later).unwrap();
    let record = manager
        .hvm_registry_channel_open(&wallet_id, later)
        .unwrap()
        .expect("the open survived");
    assert_eq!(record.countersigned_bundle(), Some(&bundle));
    let authorization = manager
        .hvm_registry_funding_authorization(&wallet_id, &node, later)
        .await
        .expect("a stored refund never expires");
    assert_eq!(authorization.amount_zhu(), DEPOSIT_ZHU);
    assert_eq!(authorization.left_address(), address);
}

/// THE SECOND CRASH WINDOW, which had no record at all before this change.
///
/// A reviewer named it: a wallet that died between broadcasting the deposit
/// and adopting the channel came back unable to tell a channel it had merely
/// authorised from one it had already paid into. The bytes are now durable
/// before they reach a node, and pressing again re-submits them rather than
/// signing a second transfer into the same channel.
#[tokio::test]
async fn a_crash_between_the_deposit_and_its_confirmation_never_signs_a_second_transfer() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let wanted = binding(&wallet.address, &hub);
    let node = HonestNode::for_channel(&wanted);
    *node.auto_mine.borrow_mut() = false;
    wallet
        .manager
        .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, wanted.clone(), &node, now)
        .await
        .expect("an honest open");
    server.abort();

    // The deposit goes on the wire and the process dies before it confirms.
    let pending = wallet
        .manager
        .fund_hvm_registry_channel(&wallet.wallet_id, &node, now)
        .await
        .expect_err("the bytes are on the wire and not in a block");
    assert!(matches!(
        pending,
        AgentWalletError::RegistryFundingNotConfirmed
    ));
    assert_eq!(node.submitted.borrow().len(), 1);
    let signed_hash = {
        let record = wallet
            .manager
            .hvm_registry_channel_open(&wallet.wallet_id, now)
            .unwrap()
            .expect("the open record");
        let funding = record
            .funding()
            .expect("THE RECORD THAT DID NOT EXIST: the wallet knows money may have left");
        assert!(!funding.is_confirmed());
        assert_eq!(funding.amount_zhu(), DEPOSIT_ZHU);
        assert_eq!(funding.contract_address(), wanted.contract_address);
        funding.transaction_hash().to_owned()
    };

    let Wallet {
        manager,
        wallet_id,
        root,
        ..
    } = wallet;
    drop(manager);
    let later = now + 3_600;
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, later).unwrap();

    // Still not in a block: the same bytes go over again, and nothing is
    // signed a second time.
    let still_pending = manager
        .fund_hvm_registry_channel(&wallet_id, &node, later)
        .await
        .expect_err("still unconfirmed");
    assert!(matches!(
        still_pending,
        AgentWalletError::RegistryFundingNotConfirmed
    ));
    assert!(
        node.submitted
            .borrow()
            .iter()
            .all(|hash| hash == &signed_hash),
        "a second transfer into one channel was signed"
    );

    // The node finally sees it, and the wallet records the block.
    node.mined.borrow_mut().push(signed_hash.clone());
    let funded = manager
        .fund_hvm_registry_channel(&wallet_id, &node, later)
        .await
        .expect("the deposit is in a block");
    assert!(funded.is_confirmed());
    assert_eq!(funded.transaction_hash(), signed_hash);

    // And pressing once more is a no-op rather than a second deposit.
    let again = manager
        .fund_hvm_registry_channel(&wallet_id, &node, later + 60)
        .await
        .expect("idempotent");
    assert_eq!(again.transaction_hash(), signed_hash);
    assert_eq!(again.confirmed_at(), funded.confirmed_at());
}

// ---------------------------------------------------------------------------
// One wallet, one channel.
// ---------------------------------------------------------------------------

/// A second channel cannot be started over a countersigned refund, because the
/// wallet cannot know whether the first was already funded and discarding the
/// record would throw away the only bill that gets that deposit back.
#[tokio::test]
async fn a_second_channel_cannot_be_started_over_a_countersigned_refund() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let wanted = binding(&wallet.address, &hub);
    let node = HonestNode::for_channel(&wanted);
    let bundle = wallet
        .manager
        .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, wanted.clone(), &node, now)
        .await
        .expect("the first channel opens");

    let mut second = wanted.clone();
    second.reuse_version += 1;
    let second_node = HonestNode::for_channel(&second);
    assert!(
        wallet
            .manager
            .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, second, &second_node, now)
            .await
            .is_err(),
        "a second channel must not replace a countersigned refund"
    );
    assert_eq!(
        wallet
            .manager
            .hvm_registry_channel_open(&wallet.wallet_id, now)
            .unwrap()
            .and_then(|record| record.countersigned_bundle().cloned()),
        Some(bundle),
        "and the first refund is untouched"
    );
    server.abort();
}

/// The wallet will not left-sign a channel it is not the left party of, and
/// will not put itself on both sides of one.
#[tokio::test]
async fn the_wallet_will_not_left_sign_a_channel_it_is_not_the_left_party_of() {
    let hub = Arc::new(account("registry-open-hub"));
    let (hub_url, server) = spawn_hub(Arc::clone(&hub), HubBehaviour::Honest).await;
    let mut wallet = open_wallet();
    let now = now_unix();
    let stranger = account("registry-open-stranger");

    let not_ours = binding(stranger.readable(), &hub);
    let node = HonestNode::for_channel(&not_ours);
    assert!(
        wallet
            .manager
            .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, not_ours, &node, now)
            .await
            .is_err()
    );

    let mut both_sides = binding(&wallet.address, &hub);
    both_sides.right_hub_address = wallet.address.clone();
    let both_node = HonestNode::for_channel(&both_sides);
    assert!(
        wallet
            .manager
            .open_hvm_registry_channel(&wallet.wallet_id, &hub_url, both_sides, &both_node, now)
            .await
            .is_err()
    );
    assert!(
        wallet
            .manager
            .hvm_registry_channel_open(&wallet.wallet_id, now)
            .unwrap()
            .is_none()
    );
    server.abort();
}
