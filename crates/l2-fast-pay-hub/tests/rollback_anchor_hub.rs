//! The external monotonic rollback anchor, end to end.
//!
//! The threat, restated so it is not lost: every safety check in this Hub is
//! enforced against its own durable state. Restore that state from an older
//! backup and every check passes again against a stale head - the Hub will
//! co-sign the same serial twice with different balances, both signatures
//! valid to the contract, and whichever reaches `finalize` first wins.
//!
//! These tests run a real witness service over real HTTP against a real Hub
//! with real durable authenticated state, sign a real bill through it, and
//! then restore the Hub from a copy of its own state directory taken before
//! that signature. The restored Hub must refuse, and the refusal must name the
//! rollback rather than something vague.

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
    HubAnchorRequestV1, HubWitnessAnswerV1, HubWitnessStatusRequestV1, RollbackAnchorClient,
    RollbackAnchorConfig, RollbackAnchorPin, SignedHubAnchorRequestV1, SignedHubWitnessReceiptV1,
    WitnessPosture,
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

/// The channel stays in its exact newly-opened on-chain shape throughout.
/// Nothing in these tests submits a transaction; the subject is the anchor.
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
    #[allow(dead_code)]
    store: TempDir,
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
        store,
    }
}

impl Witness {
    fn config(&self, hub_identity: &str, url: Option<&str>) -> RollbackAnchorConfig {
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
            witness_url: url.unwrap_or(&self.url).to_owned(),
            witness_id: self.service.witness_id().to_owned(),
            witness_epoch: self.service.witness_epoch(),
            witness_receipt_address: self.service.receipt_address().to_owned(),
            witness_authorisation_address: self.authorisation.readable().to_owned(),
            attestation,
            request_timeout: Duration::from_secs(5),
        }
    }

    fn observed_serial(&self, hub_identity: &str, binding_commitment: &str) -> Option<u64> {
        let status = self
            .service
            .status(
                &HubWitnessStatusRequestV1 {
                    hub_identity: hub_identity.to_owned(),
                    witness_id: self.service.witness_id().to_owned(),
                    nonce: "00".repeat(32),
                },
                now_unix(),
            )
            .unwrap();
        status
            .status
            .channel(binding_commitment)
            .map(|position| position.serial)
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

#[allow(clippy::too_many_arguments)]
fn build_hub(state_path: &Path, hub: &Account, node_url: &str) -> HubState {
    HubState::new_secure_with_policy(
        "rollback anchor integration",
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

/// A configured witness that cannot be reached must refuse, and it must refuse
/// by name. Silence is not a refusal and it is certainly not permission.
#[tokio::test]
async fn a_configured_but_unreachable_witness_refuses_rather_than_proceeding() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-unreachable-hub").unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x41; 20])).to_readable();
    let (_left, bundle) =
        signed_bundle("rollback-anchor-unreachable-left", &hub_account, &contract);
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let witness = spawn_witness("unreachable").await;
    let directory = tempfile::tempdir().unwrap();

    // A live client, pinned to a live witness's keys, pointed at a port that
    // answers nothing. Construction must succeed: an unreachable witness is a
    // runtime refusal, not a configuration error.
    let hub = build_hub(
        &directory.path().join("hub-state.json"),
        &hub_account,
        &node_url,
    )
    .with_rollback_anchor(witness.config(
        &Address::from(*hub_account.address()).to_readable(),
        Some("http://127.0.0.1:1"),
    ))
    .unwrap();

    let error = hub
        .run_rollback_anchor_startup_probe()
        .await
        .expect_err("an unreachable witness must refuse")
        .to_string();
    assert!(
        error.contains("rollback_anchor_witness_unreachable"),
        "the refusal must name what is wrong, got: {error}"
    );
    assert!(
        error.contains("An unreachable oracle is not evidence"),
        "the refusal must say why silence is not permission, got: {error}"
    );

    // And nothing signs while the probe has not agreed.
    hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
        .await
        .unwrap();
    let payment = left_signed_payment(&_left, &bundle, "unreachable-payment", now_unix());
    let error = hub
        .cosign_hvm_registry_payment(payment, now_unix())
        .await
        .expect_err("a Hub with an unusable anchor must not sign")
        .to_string();
    assert!(
        error.contains("startup probe has not agreed"),
        "got: {error}"
    );

    node.abort();
    witness.handle.abort();
}

/// The whole thing, in one test.
///
/// A Hub with a live witness signs. Its state directory is copied *before*
/// that signature. The copy is then opened as a Hub in its own right, which is
/// exactly what restoring from backup produces: a Hub whose every internal
/// check passes against a stale head. It must be refused, and the refusal must
/// name the rollback.
#[tokio::test]
async fn a_hub_restored_behind_the_witness_is_refused_and_the_refusal_names_the_rollback() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-restore-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x42; 20])).to_readable();
    let (left, bundle) = signed_bundle("rollback-anchor-restore-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let witness = spawn_witness("restore").await;

    let live_directory = tempfile::tempdir().unwrap();
    let backup_directory = tempfile::tempdir().unwrap();
    let state_path = live_directory.path().join("hub-state.json");

    let signed_bill = {
        let hub = build_hub(&state_path, &hub_account, &node_url)
            .with_rollback_anchor(witness.config(&hub_identity, None))
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
            .await
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        assert_eq!(
            witness.observed_serial(&hub_identity, &binding_commitment),
            None,
            "the witness has no position for this channel until a bill is reserved"
        );

        // THE BACKUP. Taken here, before the payment, exactly as an operator
        // snapshot would be.
        copy_state_directory(live_directory.path(), backup_directory.path());

        let payment = left_signed_payment(&left, &bundle, "restore-payment-1", now_unix());
        let signed = hub
            .cosign_hvm_registry_payment(payment, now_unix())
            .await
            .expect("a live witness returning valid receipts must let an honest bill through");
        assert_eq!(signed.serial, 2);
        signed
    };

    assert_eq!(
        witness.observed_serial(&hub_identity, &binding_commitment),
        Some(2),
        "the witness must hold the exact position the Hub signed"
    );

    // THE RESTORE. Every check inside this Hub passes: its ledger head is
    // fully signed, its journal verifies, its checkpoint matches. Nothing
    // local can see the problem, because nothing local is wrong.
    let restored_state = backup_directory.path().join("hub-state.json");
    let restored = build_hub(&restored_state, &hub_account, &node_url)
        .with_rollback_anchor(witness.config(&hub_identity, None))
        .unwrap();
    let error = restored
        .run_rollback_anchor_startup_probe()
        .await
        .expect_err("a Hub behind the witness must be refused before it serves anything")
        .to_string();
    assert!(
        error.contains("rollback_anchor_hub_behind_witness"),
        "the refusal must name the rollback, got: {error}"
    );
    assert!(
        error.contains("serial 2") && error.contains("serial 1"),
        "the refusal must state the gap the operator has to close, got: {error}"
    );
    assert!(
        error.contains("Do NOT re-sign"),
        "the refusal must say the one thing that must not be done at 3am, got: {error}"
    );
    assert!(
        error.contains("ROLLBACK-ANCHOR-RECOVERY.md"),
        "the refusal must point at the procedure, got: {error}"
    );

    // And the restored Hub does not sign the second bill at the same serial,
    // which is the double signature the whole design exists to prevent.
    let replay = left_signed_payment(&left, &bundle, "restore-payment-2", now_unix());
    let error = restored
        .cosign_hvm_registry_payment(replay, now_unix())
        .await
        .expect_err("the restored Hub must never co-sign serial 2 a second time")
        .to_string();
    assert!(
        error.contains("rollback_anchor_hub_behind_witness")
            || error.contains("startup probe has not agreed"),
        "got: {error}"
    );
    assert_eq!(
        witness.observed_serial(&hub_identity, &binding_commitment),
        Some(2),
        "no refused attempt may move the anchor"
    );
    assert_eq!(signed_bill.serial, 2);

    node.abort();
    witness.handle.abort();
}

/// A receipt is only a receipt if it verifies against the pinned key **and**
/// restates the exact request this Hub persisted before sending.
///
/// With the serial bound but not the bill, one receipt at serial 4 would
/// authorise *any* serial-4 bill: two different balance splits, both signed,
/// both valid to the contract. So each of these hostile answers is a signature
/// the Hub must not produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tamper {
    /// A perfectly shaped receipt signed by a key the Hub did not pin.
    UnpinnedKey,
    /// The witness's own key, over a receipt that names another serial.
    OtherSerial,
    /// The witness's own key, over a receipt that names another bill.
    OtherBill,
    /// The witness's own key, over a receipt for another Hub.
    OtherHub,
    /// Not a receipt at all.
    Garbage,
}

async fn spawn_tampering_witness(
    service: Arc<WitnessService>,
    receipt_key: Arc<Account>,
    tamper: Tamper,
) -> (String, JoinHandle<()>) {
    use axum::extract::State;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;

    /// The witness service, what to do to its answer, its real receipt key,
    /// and a key the Hub has not pinned.
    type HostileState = (Arc<WitnessService>, Tamper, Arc<Account>, Arc<Account>);

    async fn anchor(
        State((service, tamper, receipt_key, rogue)): State<HostileState>,
        Json(signed): Json<SignedHubAnchorRequestV1>,
    ) -> Response {
        if tamper == Tamper::Garbage {
            return Json(json!({"not": "a receipt"})).into_response();
        }
        let answer = service.reserve(&signed, now_unix()).unwrap();
        let HubWitnessAnswerV1::Receipt(honest) = answer else {
            return (StatusCode::INTERNAL_SERVER_ERROR, "unexpected refusal").into_response();
        };
        let mut answered = honest.receipt;
        let signer = match tamper {
            Tamper::UnpinnedKey => rogue.as_ref(),
            Tamper::OtherSerial => {
                answered.serial = answered.serial.saturating_add(1);
                receipt_key.as_ref()
            }
            Tamper::OtherBill => {
                answered.proposed_bill_commitment = "9a".repeat(32);
                receipt_key.as_ref()
            }
            Tamper::OtherHub => {
                answered.hub_identity = rogue.readable().to_owned();
                receipt_key.as_ref()
            }
            Tamper::Garbage => unreachable!(),
        };
        Json(HubWitnessAnswerV1::Receipt(Box::new(
            SignedHubWitnessReceiptV1::sign(answered, signer).unwrap(),
        )))
        .into_response()
    }

    async fn status(
        State((service, _, _, _)): State<HostileState>,
        Json(request): Json<HubWitnessStatusRequestV1>,
    ) -> Response {
        Json(service.status(&request, now_unix()).unwrap()).into_response()
    }

    let rogue = Arc::new(Account::create_by("rollback-anchor-rogue-witness-key").unwrap());
    let app = Router::new()
        .route("/witness/v1/anchor", post(anchor))
        .route("/witness/v1/status", post(status))
        .with_state((service, tamper, receipt_key, rogue));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), handle)
}

fn anchor_request(hub: &Account, witness: &Witness, counter: u64) -> SignedHubAnchorRequestV1 {
    let now = now_unix();
    let request = HubAnchorRequestV1 {
        request_version: 1,
        request_id: format!("tamper-op-{counter}"),
        hub_identity: hub.readable().to_owned(),
        witness_id: witness.service.witness_id().to_owned(),
        witness_epoch: witness.service.witness_epoch(),
        settlement_profile: "hpay-hvm-shared-registry-v2".into(),
        network_instance_id: INSTANCE.into(),
        binding_commitment: "ab".repeat(32),
        channel_id: "0123456789abcdef".into(),
        reuse_version: 0,
        serial: counter + 1,
        previous_bill_commitment: format!("{:02x}", counter).repeat(32),
        proposed_bill_commitment: format!("{:02x}", counter + 1).repeat(32),
        counter_value: counter,
        hub_journal_sequence: counter,
        hub_journal_head_hash: "cd".repeat(32),
        hub_state_commitment: "ef".repeat(32),
        created_at: now,
        expires_at: now + 60,
    };
    SignedHubAnchorRequestV1::sign(request, hub).unwrap()
}

#[tokio::test]
async fn a_malformed_or_wrongly_bound_receipt_is_refused() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub = Account::create_by("rollback-anchor-tamper-hub").unwrap();
    let hub_identity = hub.readable().to_owned();

    for (tamper, expected) in [
        (
            Tamper::UnpinnedKey,
            "signature does not verify against the pinned key",
        ),
        (
            Tamper::OtherSerial,
            "rollback_anchor_receipt_not_bound_to_request",
        ),
        (
            Tamper::OtherBill,
            "rollback_anchor_receipt_not_bound_to_request",
        ),
        (
            Tamper::OtherHub,
            "rollback_anchor_receipt_not_bound_to_request",
        ),
        (Tamper::Garbage, "rollback_anchor_witness_unreachable"),
    ] {
        let witness = spawn_witness(&format!("tamper-{tamper:?}")).await;
        let (hostile_url, hostile) = spawn_tampering_witness(
            witness.service.clone(),
            Arc::new(Account::create_by(&format!("tamper-{tamper:?}-receipt-key")).unwrap()),
            tamper,
        )
        .await;
        // Hard refusal 2 first: a Hub whose bill-signing key IS the witness
        // receipt key has no witness at all, only itself.
        let custody = RollbackAnchorClient::connect(
            witness.config(&hub_identity, Some(&hostile_url)),
            &hub_identity,
            witness.service.receipt_address(),
            "local-pilot",
        )
        .err()
        .expect("the witness receipt key must not be the Hub signing key")
        .to_string();
        assert!(
            custody.contains("rollback_anchor_witness_key_custody_is_not_distinct"),
            "got: {custody}"
        );

        // Now with distinct custody, which is the configuration under test.
        let client = RollbackAnchorClient::connect(
            witness.config(&hub_identity, Some(&hostile_url)),
            &hub_identity,
            &hub_identity,
            "local-pilot",
        )
        .unwrap();
        let error = client
            .reserve(
                &anchor_request(&hub, &witness, 1),
                &RollbackAnchorPin::default(),
                now_unix(),
            )
            .await
            .expect_err("a wrongly bound receipt must never authorise a signature")
            .to_string();
        assert!(
            error.contains(expected),
            "{tamper:?} must be refused with {expected}, got: {error}"
        );
        hostile.abort();
        witness.handle.abort();
    }
}

/// The refusal a Hub prints at 3am is only useful if the operator can look it
/// up. Every identifier the recovery document indexes its procedures by must
/// exist in the code, and every identifier the witness can name must appear in
/// the document. Neither half is allowed to drift.
#[test]
fn every_refusal_identifier_is_indexed_by_the_recovery_document() {
    use l2_fast_pay_hub::rollback_anchor::WitnessRefusalReason;

    let document = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/l2/ROLLBACK-ANCHOR-RECOVERY.md"),
    )
    .expect("the operator procedure the refusals point at must exist");

    for identifier in [
        "rollback_anchor_hub_behind_witness",
        "rollback_anchor_fork_at_serial",
        "rollback_anchor_counter_skipped",
        "rollback_anchor_witness_behind_hub",
        "rollback_anchor_witness_instance_changed",
        "rollback_anchor_witness_unreachable",
        "rollback_anchor_witness_is_not_external",
        "rollback_anchor_attestation_missing_or_expired",
    ] {
        assert!(
            document.contains(identifier),
            "{identifier} is printed by the Hub but has no entry in the recovery document"
        );
    }

    for reason in [
        WitnessRefusalReason::HubBehindWitness,
        WitnessRefusalReason::ForkAtSerial,
        WitnessRefusalReason::CounterSkipped,
        WitnessRefusalReason::WitnessBehindHub,
    ] {
        assert!(
            document.contains(reason.identifier()),
            "{} names a rollback and must be looked up in the document",
            reason.identifier()
        );
        assert!(
            reason.explanation().len() > 60,
            "{} must explain the threat in the words of the threat, not of the protocol",
            reason.identifier()
        );
    }
}
