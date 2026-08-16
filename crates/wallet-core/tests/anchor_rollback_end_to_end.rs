//! The whole rule, end to end, with nothing stubbed.
//!
//! THE THREAT. Every rollback check inside a Hub is enforced against the Hub's
//! own durable state, and the Hub also chooses which witnesses are asked. An
//! operator restores an old state file, points the Hub at a witness of their
//! choosing, and re-spends: every check passes, because every check is asked
//! of a party the operator selected. Adding more witnesses does not help, as
//! each is added by the same hand that can remove it.
//!
//! THE RULE. Every new bill must carry a receipt from at least one witness
//! that receipted the counterparty's most recently accepted bill — and, more
//! strongly here, no witness the counterparty recorded may silently disappear.
//! To re-spend past serial S the Hub must present a bill at or below S; any
//! witness that receipted the bill at S holds S and refuses. So the Hub must
//! present the new bill *without* that witness — and the overlap rule makes
//! the counterparty refuse it. The Hub is caught by the one party it cannot
//! swap out, using memory it cannot reach.
//!
//! WHAT THIS TEST RUNS. A real witness service over real HTTP, a real Hub with
//! real durable authenticated state serving `build_router`, and a real
//! `ClientL2Safety` on the payer side. A bill is co-signed with witness W and
//! recorded. The Hub's state directory is then restored from a copy taken
//! before that bill and pointed at a *different* witness E, which is what
//! "drop W entirely" looks like from outside. The restored Hub co-signs
//! happily — that is the point, it cannot see the problem — and the payer
//! refuses.
//!
//! Both ways a bill can reach the payer are exercised, because the second one
//! is what defeated this rule the first time it was built: the co-sign
//! response, and the reconciliation path a wallet takes when the Hub drops the
//! co-sign connection after signing.

#![cfg(feature = "rollback-witness")]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use field::{Address, Serialize as _, Sign};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::l2_hub::L2HubClient;
use hacash_wallet_core::l2_safety::{
    ANCHOR_WITNESS_DECISION_REQUIRED, AnchorWitnessDecision, ClientL2Safety,
};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA,
    HVM_REGISTRY_BINDING_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT, HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
    HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2,
    HvmRegistryBindingV2, HvmRegistryRecoveryBundleV2,
};
use l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryPaymentRequestV2;
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use l2_fast_pay_hub::rollback_anchor::witness::{WitnessService, WitnessServiceConfig, router};
use l2_fast_pay_hub::rollback_anchor::{
    HubWitnessStatusRequestV1, RollbackAnchorConfig, WitnessPosture,
};
use serde_json::{Value, json};
use sys::Account;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use vm::ContractAddress;

const NETWORK_KIND: &str = "local_pilot_v1";
const PROFILE_ID: &str = "hpay-local-pilot-chain-v1";
const BLOCK_ONE: &str = "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29";
const INSTANCE: &str = "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3";
const LIVE_BLOCKS: u64 = 20_000;
const RECOVER_BLOCKS: u64 = 30_000;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn secret_hex(account: &Account) -> String {
    hex::encode(account.secret_key().serialize())
}

fn capabilities(now: u64) -> Value {
    json!({
        "ret": 0,
        "api_version": 1,
        "api": { "transaction_submit_bound": true, "hpay_channel_registry_query": true },
        "chain": { "id": 7, "height": 900_000, "next_height": 900_001, "mainnet": false },
        "network": {
            "kind": NETWORK_KIND,
            "node_profile_id": PROFILE_ID,
            "block_1_hash": BLOCK_ONE,
            "instance_id": INSTANCE,
            "transaction_format_version": 2
        },
        "sync": { "tip_timestamp_unix": now, "max_tip_age_seconds": 3_600, "fresh": true },
        "actions": {
            "registered": [1, 2, 14, 40, 41, 44, 1041, 1044],
            "enabled": [1, 2, 14, 40, 41, 44, 1041, 1044]
        },
        "transactions": { "enabled": [2, 3] },
        "features": { "channel_unilateral_exit": false }
    })
}

fn network_binding() -> L1ChannelNetworkBinding {
    L1ChannelNetworkBinding::from_node_identity(
        NETWORK_KIND,
        false,
        7,
        BLOCK_ONE,
        PROFILE_ID,
        Some(INSTANCE),
        2,
    )
    .unwrap()
}

fn storage_entry(value: Value) -> Value {
    json!({
        "value": value,
        "live_blocks": LIVE_BLOCKS,
        "recover_blocks": RECOVER_BLOCKS,
        "active": true,
        "recoverable": false
    })
}

fn snapshot(binding: &HvmRegistryBindingV2) -> Value {
    json!({
        "ret": 0,
        "schema": HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA,
        "settlement_profile": HPAY_REGISTRY_SETTLEMENT_PROFILE,
        "chain_id": binding.chain_id,
        "network_instance_id": binding.network_instance_id,
        "observed_height": 900_000,
        "evaluation_height": 900_001,
        "contract_address": binding.contract_address,
        "deployment_tx_hash": binding.deployment_tx_hash,
        "deployment_height": binding.deployment_height,
        "deployment_action_verified": true,
        "bytecode_sha3": binding.bytecode_sha3,
        "hub_address": binding.right_hub_address,
        "left_address": binding.left_address,
        "registry_key_count": HVM_REGISTRY_STORAGE_KEY_COUNT,
        "channel_key_count": HVM_REGISTRY_CHANNEL_KEY_COUNT,
        "all_keys_active": true,
        "minimum_live_blocks": LIVE_BLOCKS,
        "minimum_recover_blocks": RECOVER_BLOCKS,
        "registry": {
            "g_network": storage_entry(json!(binding.network_instance_id)),
            "g_hub": storage_entry(json!(binding.right_hub_address)),
            "g_locked": storage_entry(json!(binding.left_deposit_zhu)),
            "g_left_claimable": storage_entry(json!(0)),
            "g_hub_claimable": storage_entry(json!(0)),
            "g_open_count": storage_entry(json!(1))
        },
        "channel": {
            "status": storage_entry(json!(2)),
            "channel_id": storage_entry(json!(binding.channel_id)),
            "reuse": storage_entry(json!(binding.reuse_version)),
            "deposit": storage_entry(json!(binding.left_deposit_zhu)),
            "paid": storage_entry(json!(binding.left_deposit_zhu)),
            "total": storage_entry(json!(binding.left_deposit_zhu)),
            "serial": storage_entry(json!(0)),
            "left_balance": storage_entry(json!(binding.left_deposit_zhu)),
            "hub_balance": storage_entry(json!(0)),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks)),
            "deadline": storage_entry(json!(0)),
            "left_claimed": storage_entry(json!(false))
        }
    })
}

fn signed_bundle(
    seed: &str,
    hub: &Account,
    contract: &str,
) -> (Account, HvmRegistryRecoveryBundleV2) {
    let left = Account::create_by(seed).unwrap();
    let binding = HvmRegistryBindingV2 {
        schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: 7,
        network_instance_id: INSTANCE.into(),
        contract_address: contract.into(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
        channel_id: hex::encode(sys::sha2(seed.as_bytes()))[..32].into(),
        reuse_version: 0,
        left_address: Address::from(*left.address()).to_readable(),
        right_hub_address: Address::from(*hub.address()).to_readable(),
        left_deposit_zhu: 1_000_000,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    };
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().unwrap(),
        serial: 1,
        left_balance_zhu: binding.left_deposit_zhu,
        hub_balance_zhu: 0,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(&binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(hub, &hash).serialize());
    (
        left,
        HvmRegistryRecoveryBundleV2 {
            schema: HVM_REGISTRY_RECOVERY_BUNDLE_SCHEMA.into(),
            binding,
            initial_recovery_bill: bill,
        },
    )
}

/// The payer's own signed proposal. Deliberately built from the *initial*
/// recovery bill in every case, so the honest Hub and the restored Hub are
/// offered byte-identical proposals at serial 2: the only thing that differs
/// between them is which witness receipts come back.
fn left_signed_payment(
    left: &Account,
    bundle: &HvmRegistryRecoveryBundleV2,
    operation_id: &str,
    now: u64,
) -> HvmRegistryPaymentRequestV2 {
    let mut request = HvmRegistryPaymentRequestV2::build_unsigned(
        &network_binding(),
        &bundle.binding,
        &bundle.initial_recovery_bill,
        operation_id,
        &format!("{operation_id}-idempotency"),
        &bundle.binding.right_hub_address,
        100_000,
        now,
        now + 300,
    )
    .unwrap();
    let hash = request.proposed_bill.signing_hash(&bundle.binding).unwrap();
    request.proposed_bill.left_signature_hex =
        hex::encode(Sign::create_by(left, &hash).serialize());
    let authorization_hash = request
        .payer_authorization_hash(&bundle.binding, &bundle.initial_recovery_bill)
        .unwrap();
    request.payer_authorization_signature_hex =
        hex::encode(Sign::create_by(left, &authorization_hash).serialize());
    request
}

async fn spawn_node(binding: HvmRegistryBindingV2) -> (String, JoinHandle<()>) {
    let expected = binding.clone();
    let live = snapshot(&binding);
    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async { Json(capabilities(now_unix())) }),
        )
        .route(
            "/query/hpay/channel-registry",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let live = live.clone();
                let expected = expected.clone();
                async move {
                    let exact = query.get("contract") == Some(&expected.contract_address)
                        && query.get("deployment_tx_hash") == Some(&expected.deployment_tx_hash)
                        && query.get("deployment_height")
                            == Some(&expected.deployment_height.to_string())
                        && query.get("left") == Some(&expected.left_address);
                    if exact {
                        (StatusCode::OK, Json(live))
                    } else {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"ret": 1, "err": "binding mismatch"})),
                        )
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), handle)
}

struct Witness {
    url: String,
    service: Arc<WitnessService>,
    handle: JoinHandle<()>,
    authorisation: Account,
    _store: TempDir,
}

async fn spawn_witness(seed: &str) -> Witness {
    let store = tempfile::tempdir().unwrap();
    let service = Arc::new(
        WitnessService::open(
            WitnessServiceConfig {
                witness_id: format!("witness-{seed}"),
                witness_epoch: 1,
                store_path: store.path().join("witness-log.jsonl"),
                receipt_account: Account::create_by(&format!("{seed}-receipt-key")).unwrap(),
            },
            now_unix(),
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = service.clone();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(served)).await;
    });
    Witness {
        url: format!("http://{address}"),
        service,
        handle,
        authorisation: Account::create_by(&format!("{seed}-offline-authorisation-key")).unwrap(),
        _store: store,
    }
}

impl Witness {
    fn config(&self, hub_identity: &str) -> RollbackAnchorConfig {
        let attestation = self
            .service
            .issue_attestation(
                &self.authorisation,
                hub_identity,
                WitnessPosture::NeutralThirdParty,
                "Example Neutral Witness Co",
                "separate operator, separate hosting, separate backup set, offline authorisation \
                 key held by a different named person",
                now_unix(),
                30 * 86_400,
            )
            .unwrap();
        RollbackAnchorConfig {
            witness_url: self.url.clone(),
            witness_id: self.service.witness_id().to_owned(),
            witness_epoch: self.service.witness_epoch(),
            witness_receipt_address: self.service.receipt_address().to_owned(),
            witness_authorisation_address: self.authorisation.readable().to_owned(),
            attestation,
            request_timeout: Duration::from_secs(5),
        }
    }

    fn instance_id(&self, hub_identity: &str) -> String {
        self.service
            .status(
                &HubWitnessStatusRequestV1 {
                    hub_identity: hub_identity.to_owned(),
                    witness_id: self.service.witness_id().to_owned(),
                    nonce: "00".repeat(32),
                },
                now_unix(),
            )
            .unwrap()
            .status
            .witness_instance_id
    }
}

fn copy_state_directory(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

fn build_hub(state_path: &Path, hub: &Account, node_url: &str) -> HubState {
    HubState::new_secure_with_policy(
        "rollback anchor counterparty ratchet",
        Address::from(*hub.address()).to_readable(),
        node_url.to_owned(),
        None,
        state_path.to_path_buf(),
        secret_hex(hub),
        &"11".repeat(32),
        &"22".repeat(32),
        "local-pilot",
        0,
        0,
    )
    .unwrap()
}

async fn serve(hub: HubState) -> (String, JoinHandle<()>) {
    let hub = Arc::new(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, l2_fast_pay_hub::build_router(hub)).await;
    });
    (format!("http://{address}"), handle)
}

/// One payer's durable L2 store, opened the way a wallet opens it.
struct Payer {
    _root: TempDir,
    account: WalletAccount,
    root: std::path::PathBuf,
    scope: String,
    hub_identity: String,
    channel_id: String,
}

impl Payer {
    fn new(passphrase: &str, hub_identity: &str, channel_id: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let account = WalletAccount::create(passphrase).unwrap();
        let scope = format!("personal:{}", account.address());
        let path = root.path().join("l2");
        Self {
            _root: root,
            account,
            root: path,
            scope,
            hub_identity: hub_identity.to_owned(),
            channel_id: channel_id.to_owned(),
        }
    }

    fn open(&self) -> ClientL2Safety {
        ClientL2Safety::open_scoped_with_key_provider_for_network(
            &self.account,
            &self.root,
            &self.scope,
            "testnet",
            &self.hub_identity,
            &self.channel_id,
        )
        .unwrap()
    }
}

/// THE TEST THIS WHOLE SUBSYSTEM EXISTS FOR.
#[tokio::test]
async fn a_hub_that_drops_the_witness_which_signed_the_last_bill_is_refused_by_the_payer() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("counterparty-ratchet-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x51; 20])).to_readable();
    let (left, bundle) = signed_bundle("counterparty-ratchet-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;

    // W is the witness that will receipt the payer's bill. E is the witness
    // the operator adopts afterwards - a different key, a different store, and
    // from the Hub's own point of view a perfectly valid one.
    let honest_witness = spawn_witness("honest").await;
    let attacker_witness = spawn_witness("attacker").await;

    let live_directory = tempfile::tempdir().unwrap();
    let backup_directory = tempfile::tempdir().unwrap();
    let state_path = live_directory.path().join("hub-state.json");

    // The channel is activated before any anchor is attached, and the backup
    // is taken there. That is what makes the restored Hub able to adopt a
    // different witness at all: its pinned witness identity is still empty,
    // exactly as it would be for an operator restoring a snapshot taken before
    // they first configured a witness.
    {
        let hub = build_hub(&state_path, &hub_account, &node_url);
        hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
            .await
            .unwrap();
    }
    copy_state_directory(live_directory.path(), backup_directory.path());

    // ---------------------------------------------------------------- honest
    let honest_hub = build_hub(&state_path, &hub_account, &node_url)
        .with_rollback_anchor(honest_witness.config(&hub_identity))
        .unwrap();
    honest_hub.run_rollback_anchor_startup_probe().await.unwrap();
    let (honest_url, honest_server) = serve(honest_hub).await;
    let honest_client = L2HubClient::new_for_wallet_policy(honest_url.clone(), "testnet", false);

    // Two payer stores, because there are two ways a bill reaches a wallet and
    // both have to be proven. `co_sign` learns its head from the co-sign
    // response; `reconcile` learns it from the status document after the Hub
    // drops the co-sign connection. Historically only the first was checked,
    // and the second was how the whole rule was defeated.
    let co_sign_payer = Payer::new("ratchet-payer-cosign", &hub_identity, &binding_commitment);
    let reconcile_payer =
        Payer::new("ratchet-payer-reconcile", &hub_identity, &binding_commitment);

    let honest_payment = left_signed_payment(&left, &bundle, "honest-payment", now_unix());
    let honest_commitment = honest_payment.proposed_bill.commitment().unwrap();

    let mut store = co_sign_payer.open();
    let bill = honest_client
        // Floor 0: the payer has committed no bill on this channel yet. The
        // activation bill at serial 1 was never anchored and is not a payment.
        .cosign_hvm_registry_payment(&honest_payment, &mut store, &hub_identity, 0)
        .await
        .expect("an honest bill, receipted by the witness the payer will remember, must pass");
    assert_eq!(bill.serial, 2);
    let remembered = store.anchor_memory(&binding_commitment).unwrap();
    assert_eq!(remembered.accepted_serial, 2);
    assert_eq!(remembered.accepted_bill_commitment, honest_commitment);
    assert_eq!(remembered.witnesses.len(), 1);
    let recorded = remembered.witnesses.values().next().unwrap();
    assert_eq!(
        recorded.signer_address,
        honest_witness.service.receipt_address(),
        "the recorded identity must be the address recovered from the signature"
    );
    assert_eq!(
        recorded.witness_instance_id,
        honest_witness.instance_id(&hub_identity)
    );
    drop(store);

    // The second payer store records the same head. It is seeded through the
    // co-sign path deliberately, so that when this store is later reconciled
    // against the restored Hub, the reconcile call is the only thing under
    // test — remove the ratchet from reconciliation and it is that refusal
    // that fails, not the setup.
    let mut store = reconcile_payer.open();
    honest_client
        .cosign_hvm_registry_payment(&honest_payment, &mut store, &hub_identity, 0)
        .await
        .expect("the Hub answers a repeat of the exact same request idempotently");
    assert_eq!(
        store
            .anchor_memory(&binding_commitment)
            .unwrap()
            .accepted_bill_commitment,
        honest_commitment
    );

    // And reconciling that same head must still pass: this is the crash window
    // a wallet lands in when it dies between the Hub signing and its own
    // persist, and it has to stay open or the channel is stuck with no honest
    // way out.
    let status = honest_client
        .reconcile_hvm_registry_payment(
            "honest-payment",
            &honest_payment,
            &mut store,
            &hub_identity,
            2,
        )
        .await
        .expect("reconciling the exact recorded head, fully receipted, must pass");
    assert_eq!(status.status, "fully_signed");
    drop(store);
    honest_server.abort();

    // ------------------------------------------------------------- restored
    // The operator restores the state directory from before that bill and
    // points the Hub at witness E. W is gone: not unreachable, not refusing -
    // simply no longer asked. Nothing inside this Hub can see a problem,
    // because from inside there is none: its ledger head is fully signed, its
    // journal verifies, and its witness answers.
    let restored_hub = build_hub(
        &backup_directory.path().join("hub-state.json"),
        &hub_account,
        &node_url,
    )
    .with_rollback_anchor(attacker_witness.config(&hub_identity))
    .unwrap();
    restored_hub
        .run_rollback_anchor_startup_probe()
        .await
        .expect("a restored Hub with a fresh witness passes its own startup probe");
    let (restored_url, restored_server) = serve(restored_hub).await;
    let restored_client = L2HubClient::new_for_wallet_policy(restored_url.clone(), "testnet", false);

    let replay = left_signed_payment(&left, &bundle, "replay-payment", now_unix());
    assert_eq!(
        replay.proposed_bill.commitment().unwrap(),
        honest_commitment,
        "the replayed proposal is byte-identical to the accepted one, so the only difference \
         between the two bills is which witness receipted them"
    );

    // 1. THE CO-SIGN PATH.
    let mut store = co_sign_payer.open();
    let error = restored_client
        // Floor 2: this payer's own history, held outside this store, now says
        // the channel reached serial 2.
        .cosign_hvm_registry_payment(&replay, &mut store, &hub_identity, 2)
        .await
        .expect_err("a bill from a Hub that dropped the payer's witness must not be accepted")
        .to_string();
    assert!(
        error.contains(ANCHOR_WITNESS_DECISION_REQUIRED),
        "the refusal must be the parked witness-set decision, got: {error}"
    );
    assert!(
        error.contains("no longer shares any witness with the one that signed your last bill"),
        "and it must say plainly what happened, got: {error}"
    );

    // The Hub did co-sign it. The refusal is the payer's, made against a
    // cryptographically valid receipt from a witness of the Hub's choosing -
    // not a malformed message, not a Hub-side check.
    let served: Value = reqwest::Client::new()
        .get(format!(
            "{restored_url}/v2/hvm-registry/payment/replay-payment"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(served.get("status").and_then(Value::as_str), Some("fully_signed"));
    let receipts = served
        .get("anchor_receipts")
        .and_then(Value::as_array)
        .expect("the restored Hub attaches its own witness's receipt");
    assert_eq!(receipts.len(), 1);
    let offered: l2_fast_pay_hub::rollback_anchor::SignedHubWitnessReceiptV1 =
        serde_json::from_value(receipts[0].clone()).unwrap();
    offered
        .verify_against_pinned_key(attacker_witness.service.receipt_address())
        .expect("the receipt the payer refused is a valid one, from the wrong witness");

    // Nothing moved, and the evidence a person needs is durable.
    let parked = store.anchor_memory(&binding_commitment).unwrap();
    assert_eq!(parked.accepted_serial, 2);
    assert_eq!(parked.accepted_bill_commitment, honest_commitment);
    let change = store
        .pending_anchor_decision(&binding_commitment)
        .expect("the decision must be parked durably, not returned and forgotten");
    assert!(change.is_zero_overlap());
    assert_eq!(change.dropped.len(), 1);
    assert_eq!(
        change.dropped[0].signer_address,
        honest_witness.service.receipt_address()
    );
    assert_eq!(change.offered.len(), 1);
    assert_eq!(
        change.offered[0].signer_address,
        attacker_witness.service.receipt_address()
    );
    drop(store);

    // 2. THE RECONCILE PATH — the same bill, reached the other way.
    // A Hub that co-signs and then drops the connection sends the wallet here.
    // This store has no parked decision, so the refusal below is the overlap
    // rule itself and nothing else.
    let mut store = reconcile_payer.open();
    assert!(store.pending_anchor_decision(&binding_commitment).is_none());
    let error = restored_client
        .reconcile_hvm_registry_payment(
            "replay-payment",
            &replay,
            &mut store,
            &hub_identity,
            2,
        )
        .await
        .expect_err("reconciling must run the same ratchet, or it is a door around it")
        .to_string();
    assert!(
        error.contains(ANCHOR_WITNESS_DECISION_REQUIRED),
        "unexpected error: {error}"
    );
    assert_eq!(
        store
            .anchor_memory(&binding_commitment)
            .unwrap()
            .accepted_bill_commitment,
        honest_commitment,
        "reconciliation must not advance the head it just refused"
    );

    // 3. THE ANSWER. Closing stays available and is a real answer: the channel
    // latches on its last accepted bill, whose receipt set is intact, and
    // refuses to advance afterwards.
    store
        .resolve_anchor_witness_change(&binding_commitment, AnchorWitnessDecision::CloseChannel)
        .unwrap();
    let closed = store.anchor_memory(&binding_commitment).unwrap();
    assert!(closed.closing);
    assert_eq!(closed.accepted_serial, 2);
    assert_eq!(closed.accepted_bill_commitment, honest_commitment);
    let error = restored_client
        .reconcile_hvm_registry_payment(
            "replay-payment",
            &replay,
            &mut store,
            &hub_identity,
            2,
        )
        .await
        .expect_err("a closing channel does not advance")
        .to_string();
    assert!(error.contains("closing"), "unexpected error: {error}");
    drop(store);

    // 4. THE OTHER ANSWER. Accepting is available too, and is not a no-op: the
    // new set becomes the baseline and the dropped witness is retired rather
    // than erased, so the event survives in the record.
    let mut store = co_sign_payer.open();
    store
        .resolve_anchor_witness_change(
            &binding_commitment,
            AnchorWitnessDecision::AcceptNewWitnessSet,
        )
        .unwrap();
    let accepted = store.anchor_memory(&binding_commitment).unwrap();
    assert!(accepted.pending_decision.is_none());
    assert_eq!(accepted.witnesses.len(), 1);
    assert_eq!(
        accepted.witnesses.values().next().unwrap().signer_address,
        attacker_witness.service.receipt_address()
    );
    assert_eq!(accepted.retired.len(), 1);
    assert_eq!(
        accepted.retired.values().next().unwrap().signer_address,
        honest_witness.service.receipt_address(),
        "the dropped witness must be retired, never erased"
    );

    restored_server.abort();
    node.abort();
    honest_witness.handle.abort();
    attacker_witness.handle.abort();
}
