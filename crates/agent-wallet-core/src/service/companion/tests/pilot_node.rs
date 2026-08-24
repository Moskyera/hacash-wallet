//! The one mock Local Pilot node the pilot tests drive, and the wallet, phone
//! and receipt helpers that go with it.
//!
//! This used to live inside `witness.rs`. It is a module of its own because the
//! desktop-approval end-to-end test needs the same node, and a second copy of a
//! capability document, a balance shape or a transaction builder is a copy that
//! can silently disagree with the first about what a real node does.
//!
//! Two routes here are what let a test drive the REAL signing path rather than
//! writing `signed_awaiting_witness` into state by hand:
//!
//!   * `/query/balance` funds whichever wallet the test just created, so
//!     `create_payment_intent` gets past its own affordability check.
//!   * `/create/transaction` answers with a genuine consensus Type 2 body built
//!     from the exact request. It has to be genuine: the signer decodes the
//!     body it is handed, re-verifies the main address, the fee and every
//!     action against the approved intent, and refuses anything else. A stub
//!     body would prove nothing about signing.
//!
//! The node never signs and never has a key. It builds unsigned bodies only,
//! which is exactly the trust boundary the production code assumes.

use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    extract::Query,
    routing::{get, post},
};
use basis::interface::Transaction as _;
use field::{Address, Amount, Serialize as _};
use hpay_companion_protocol::{
    DevicePermission, SignedRollbackAnchor, SignedWitnessReceipt, SoftwareDeviceIdentity,
    WitnessReceipt,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sys::ToHex as _;
use tokio::sync::RwLock;

use super::fixtures::*;
use super::*;

/// Fixed so a built body is reproducible across runs. The wallet never reads a
/// transaction timestamp for any decision; it binds the main address, the fee
/// and the actions.
const MOCK_TX_TIMESTAMP: u64 = 1_730_000_000;

pub(super) struct MockPilotNode {
    pub(super) url: String,
    pub(super) capabilities: Arc<RwLock<Value>>,
    pub(super) submit_count: Arc<AtomicUsize>,
    pub(super) submitted_bodies: Arc<RwLock<Vec<String>>>,
    /// Bodies that arrived on `/submit/transaction/hpay-bound`, the route the
    /// owner's independent voucher broadcast uses.
    pub(super) bound_submitted_bodies: Arc<RwLock<Vec<String>>>,
    pub(super) bound_submit_count: Arc<AtomicUsize>,
    /// When set, the node acknowledges a submission with a transaction hash
    /// that is not the one the wallet signed. That is the real production
    /// route into `BroadcastUncertain`: the bytes went out, the acknowledgement
    /// cannot be tied to them.
    pub(super) submit_hash_mismatch: Arc<AtomicBool>,
    channels: Arc<RwLock<HashMap<String, Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockPilotNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockPilotNode {
    pub(super) async fn set_capabilities(&self, capabilities: Value) {
        *self.capabilities.write().await = capabilities;
    }

    pub(super) async fn set_channel(&self, channel_id: String, channel: Value) {
        self.channels.write().await.insert(channel_id, channel);
    }
}

#[derive(Deserialize)]
struct ChannelQuery {
    id: Option<String>,
}

pub(super) fn official_capabilities() -> Value {
    let tip_timestamp_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("test clock must be after the Unix epoch")
        .as_secs();
    let instance_id = hacash_wallet_core::network_instance_id(
        hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
        hacash_wallet_core::HPAY_LOCAL_PILOT_CHAIN_ID,
        false,
        TESTNET_ANCHOR,
        hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
        2,
    );
    json!({
        "ret": 0,
        "api_version": 1,
        "node": { "name": "hacash-fullnode", "version": "1.0.10", "build_time": "test" },
        "chain": { "id": 7, "height": 10, "next_height": 11, "mainnet": false },
        "network": {
            "kind": hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
            "node_profile_id": hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
            "block_1_available": true,
            "block_1_hash": TESTNET_ANCHOR,
            "instance_id": instance_id,
            "funding_confirmed": true,
            "transaction_ready": true,
            "current_height": 10,
            "transaction_format_version": 2
        },
        "sync": {
            "fresh": true,
            "tip_timestamp_unix": tip_timestamp_unix,
            "observed_unix": tip_timestamp_unix,
            "tip_age_seconds": 0,
            "max_tip_age_seconds": l2_fast_pay_hub::node::FULLNODE_MAX_TIP_AGE_SECONDS
        },
        "istanbul": { "activation_height": 1, "evaluation_height": 11, "active": true },
        "transactions": { "registered": [2, 3], "enabled": [2, 3] },
        "actions": { "registered": [1, 2, 3, 14, 1041], "enabled": [1, 2, 3, 14, 1041] },
        "features": {
            "action_guard": false, "tx_blob": false, "ast": false, "tex": false,
            "native_assets": false, "hip20": false, "hip20_primitives": false,
            "hvm": false, "p2sh": false, "account_abstraction": false,
            "intent": false, "contract_state_leasing": false,
            "ir_decompilation": false, "req_sign_list": false,
            "type4_mainnet": false, "exact_unsigned_simulation": false
        },
        "api": {
            "balance_query": true,
            "transaction_submit": true,
            "transaction_submit_bound": true,
            "transaction_query": true,
            "reconciliation_by_tx_hash": true
        },
        "limits": {
            "max_tx_size": 1024, "max_tx_actions": 8, "max_type3_signers": 2,
            "gas_max_byte": 1,
            "gas_max": protocol::context::decode_gas_budget(1),
            "ast_depth": 1
        }
    })
}

/// A real, unsigned, consensus-serialized Type 2 transaction for exactly the
/// request the wallet posted. Returns `None` for anything outside the pilot's
/// supported surface (HAC transfers only), which the caller reports as a node
/// refusal rather than a body the wallet would then have to reject.
fn build_unsigned_type2_body(payload: &Value) -> Option<String> {
    let main = Address::from_readable(payload.get("main_address")?.as_str()?).ok()?;
    let fee = Amount::from(payload.get("fee")?.as_str()?).ok()?;
    let mut transaction =
        protocol::transaction::TransactionType2::new_by(main, fee, MOCK_TX_TIMESTAMP);
    let actions = payload.get("actions")?.as_array()?;
    if actions.is_empty() {
        return None;
    }
    for action in actions {
        if action.get("kind")?.as_u64()? != 1 {
            return None;
        }
        let to = Address::from_readable(action.get("to")?.as_str()?).ok()?;
        let hacash = Amount::from(action.get("hacash")?.as_str()?).ok()?;
        transaction
            .push_action(Box::new(protocol::action::HacToTrs::create_by(to, hacash)))
            .ok()?;
    }
    Some(transaction.serialize().to_hex())
}

pub(super) async fn spawn_pilot_node() -> MockPilotNode {
    let capabilities = Arc::new(RwLock::new(official_capabilities()));
    let submit_count = Arc::new(AtomicUsize::new(0));
    let submitted_bodies = Arc::new(RwLock::new(Vec::new()));
    let bound_submit_count = Arc::new(AtomicUsize::new(0));
    let bound_submitted_bodies = Arc::new(RwLock::new(Vec::new()));
    let submit_hash_mismatch = Arc::new(AtomicBool::new(false));
    let channels = Arc::new(RwLock::new(HashMap::<String, Value>::new()));
    let capability_state = capabilities.clone();
    let submit_state = submit_count.clone();
    let submitted_body_state = submitted_bodies.clone();
    let bound_submit_state = bound_submit_count.clone();
    let bound_submitted_body_state = bound_submitted_bodies.clone();
    let mismatch_state = submit_hash_mismatch.clone();
    let channel_state = channels.clone();
    let app = Router::new()
        .route(
            "/query/channel",
            get(move |Query(query): Query<ChannelQuery>| {
                let channel_state = channel_state.clone();
                async move {
                    let channel_id = query.id.unwrap_or_default();
                    let channels = channel_state.read().await;
                    Json(
                        channels
                            .get(&channel_id)
                            .cloned()
                            .unwrap_or_else(|| json!({ "ret": 1, "err": "channel not found" })),
                    )
                }
            }),
        )
        .route(
            "/query/block/intro",
            get(|| async {
                Json(json!({
                    "ret": 0,
                    "height": 1,
                    "hash": TESTNET_ANCHOR
                }))
            }),
        )
        .route(
            "/query/capabilities",
            get(move || {
                let capability_state = capability_state.clone();
                async move { Json(capability_state.read().await.clone()) }
            }),
        )
        .route(
            // One entry with no address is the older-node shape the client
            // accepts for a single-address query, so this funds whichever
            // wallet the test creates without the test knowing its address.
            "/query/balance",
            get(|| async { Json(json!({ "ret": 0, "list": [{ "hacash": "1000" }] })) }),
        )
        .route(
            "/create/transaction",
            post(|Json(payload): Json<Value>| async move {
                match build_unsigned_type2_body(&payload) {
                    Some(body) => Json(json!({ "ret": 0, "body": body })),
                    None => Json(json!({
                        "ret": 1,
                        "err": "test node builds HAC Type 2 transfers only"
                    })),
                }
            }),
        )
        .route(
            "/submit/transaction",
            post(move |body: String| {
                let submit_state = submit_state.clone();
                let submitted_body_state = submitted_body_state.clone();
                let mismatch_state = mismatch_state.clone();
                async move {
                    submitted_body_state.write().await.push(body);
                    submit_state.fetch_add(1, Ordering::SeqCst);
                    if mismatch_state.load(Ordering::SeqCst) {
                        return Json(json!({
                            "ret": 0,
                            "hash": "00000000000000000000000000000000000000000000000000000000deadbeef"
                        }));
                    }
                    Json(json!({ "ret": 0 }))
                }
            }),
        )
        .route(
            // The network-bound submit the owner's own voucher broadcast uses.
            // It records the exact bytes so a test can prove the owner reached
            // a chain without the Hub, and echoes back the hash the node would
            // acknowledge.
            "/submit/transaction/hpay-bound",
            post(move |body: String| {
                let submit_state = bound_submit_state.clone();
                let submitted_body_state = bound_submitted_body_state.clone();
                async move {
                    submitted_body_state.write().await.push(body.clone());
                    submit_state.fetch_add(1, Ordering::SeqCst);
                    let hash = hex::decode(&body)
                        .ok()
                        .and_then(|raw| {
                            protocol::transaction::transaction_create(&raw)
                                .ok()
                                .map(|(transaction, _)| {
                                    hex::encode(
                                        basis::interface::TransactionRead::hash(&*transaction)
                                            .as_bytes(),
                                    )
                                })
                        })
                        .unwrap_or_default();
                    Json(json!({ "ret": 0, "hash": hash }))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockPilotNode {
        url,
        capabilities,
        submit_count,
        submitted_bodies,
        bound_submitted_bodies,
        bound_submit_count,
        submit_hash_mismatch,
        channels,
        task,
    }
}

pub(super) fn create_manager_for_node(
    node_url: &str,
    now: u64,
) -> (tempfile::TempDir, AgentWalletManager, AgentWalletId) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.to_owned(),
                network_mode: "testnet".to_owned(),
                node_url: node_url.to_owned(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.to_owned()),
                mainnet_pilot_acknowledgement: None,
            },
            now,
        )
        .unwrap();
    manager
        .unlock(&created.wallet_id, PASSPHRASE, now + 1)
        .unwrap();
    manager
        .enable_agent_payments_locally(&created.wallet_id, now + 2)
        .unwrap();
    (root, manager, created.wallet_id)
}

pub(super) fn register_witness_mobile(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) {
    let permissions = BTreeSet::from([DevicePermission::WitnessRollbackAnchor]);
    let record = mobile
        .public_record(wallet_id.as_str(), permissions, now)
        .unwrap();
    manager
        .register_verified_companion_device(wallet_id, record, now)
        .unwrap();
}

pub(super) async fn signed_receipt(
    proposal: &SignedRollbackAnchor,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) -> SignedWitnessReceipt {
    let anchor_hash = proposal.anchor.canonical_sha256_hex().unwrap();
    let receipt = WitnessReceipt::for_anchor(&proposal.anchor, anchor_hash, now).unwrap();
    SignedWitnessReceipt::sign(receipt, mobile).await.unwrap()
}
