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

/// The same proposal, built against a head that has already moved.
///
/// [`left_signed_payment`] always builds on the channel's initial recovery
/// bill, so on a channel that has taken a payment it is refused by the ledger
/// as a stale `previous_bill_commitment` - long before the anchor is consulted.
/// A test that wants to prove the *anchor* refuses has to get past the ledger
/// first, which means proposing on the real head.
fn left_signed_payment_on_head(
    left: &Account,
    bundle: &HvmRegistryRecoveryBundleV2,
    previous: &HvmRegistryBillV2,
    operation_id: &str,
    now: u64,
) -> HvmRegistryPaymentRequestV2 {
    let mut request = HvmRegistryPaymentRequestV2::build_unsigned(
        &network_binding(),
        &bundle.binding,
        previous,
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
        .payer_authorization_hash(&bundle.binding, previous)
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
    store: Option<TempDir>,
}

async fn spawn_witness(seed: &str) -> Witness {
    let store = tempfile::tempdir().unwrap();
    let path = store.path().join("witness-log.jsonl");
    spawn_witness_at(seed, Some(store), path).await
}

/// The same witness, with its durable store put exactly where the test wants
/// it - including, deliberately, inside the Hub's own state directory. `store`
/// is `None` when the caller owns the directory the store lives in.
async fn spawn_witness_at(
    seed: &str,
    store: Option<TempDir>,
    store_path: std::path::PathBuf,
) -> Witness {
    let service = Arc::new(
        WitnessService::open(
            WitnessServiceConfig {
                witness_id: format!("witness-{seed}"),
                witness_epoch: 1,
                store_path,
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

    /// The identity of the witness's durable store. Half of the pair key the
    /// counterparty ratchets on, and the half a re-provisioned store changes.
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
        assert_eq!(signed.bill.serial, 2);
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
    assert_eq!(signed_bill.bill.serial, 2);

    node.abort();
    witness.handle.abort();
}

/// Removing the witness configuration must not un-condemn a channel.
///
/// This is the cheapest attack on the whole subsystem and it needs no
/// cryptography: catch a Hub in a real rollback, let it latch the channel into
/// its own `hub-state.json`, then delete the five `--rollback-witness-*` flags
/// and start it again. The anchor client is gone, so if the latch is only ever
/// read *after* the "no anchor configured" exit, it is never read at all - and
/// the condemned channel co-signs the already-signed serial a second time with
/// different balances. Both signatures are valid to the contract, whichever
/// reaches `finalize` first wins, and the counterparty's money is gone.
///
/// A latch lives in the Hub's own durable state, not in the anchor client.
/// ADR-001 forbids a bypass by name, and a flag you can delete is the purest
/// possible bypass.
///
/// The second half of the test is the part that keeps this honest: a Hub that
/// never had an anchor holds no latches, and must sign exactly as it always
/// did. This check condemns channels that were condemned; it does not invent a
/// new anchor requirement for Hubs that never had one.
#[tokio::test]
async fn removing_the_witness_configuration_does_not_un_condemn_a_latched_channel() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-unlatch-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x44; 20])).to_readable();
    let (left, bundle) = signed_bundle("rollback-anchor-unlatch-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let witness = spawn_witness("unlatch").await;

    let live_directory = tempfile::tempdir().unwrap();
    let backup_directory = tempfile::tempdir().unwrap();
    let state_path = live_directory.path().join("hub-state.json");

    // A live, honest Hub signs serial 2, with a backup taken just before.
    {
        let hub = build_hub(&state_path, &hub_account, &node_url)
            .with_rollback_anchor(witness.config(&hub_identity, None))
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
            .await
            .unwrap();
        copy_state_directory(live_directory.path(), backup_directory.path());
        let payment = left_signed_payment(&left, &bundle, "unlatch-payment-1", now_unix());
        let signed = hub
            .cosign_hvm_registry_payment(payment, now_unix())
            .await
            .unwrap();
        assert_eq!(signed.bill.serial, 2);
    }
    assert_eq!(
        witness.observed_serial(&hub_identity, &binding_commitment),
        Some(2)
    );

    // THE ROLLBACK, caught. The refusal latches into the restored state file.
    let restored_state = backup_directory.path().join("hub-state.json");
    {
        let restored = build_hub(&restored_state, &hub_account, &node_url)
            .with_rollback_anchor(witness.config(&hub_identity, None))
            .unwrap();
        let error = restored
            .run_rollback_anchor_startup_probe()
            .await
            .expect_err("a Hub behind the witness must be refused")
            .to_string();
        assert!(
            error.contains("rollback_anchor_hub_behind_witness"),
            "{error}"
        );
    }

    // The latching Hub is dropped above. Everything that follows reads the
    // condemnation back off disk into a fresh `HubState`, which is what makes
    // this a test of durable state rather than of a live process.

    // THE EDIT. The five --rollback-witness-* flags are gone; everything else
    // is byte-identical. `rollback_anchor_config` returns `Ok(None)` and the
    // Hub is built with no anchor at all.
    let unanchored = build_hub(&restored_state, &hub_account, &node_url);
    assert!(
        !unanchored.rollback_anchor_configured(),
        "this is the un-anchored Hub the operator just created"
    );

    let replay = left_signed_payment(&left, &bundle, "unlatch-payment-2", now_unix());
    let error = unanchored
        .cosign_hvm_registry_payment(replay, now_unix())
        .await
        .expect_err(
            "a durable condemnation must be honoured whether or not an anchor is configured - \
             otherwise the strongest refusal in this system is undone with a text editor",
        )
        .to_string();
    assert!(
        error.contains("rollback_anchor_hub_behind_witness"),
        "the refusal must still name the rollback that condemned the channel, got: {error}"
    );
    assert!(
        error.contains("ROLLBACK-ANCHOR-RECOVERY.md"),
        "and must still point at the procedure that clears it, got: {error}"
    );
    assert_eq!(
        witness.observed_serial(&hub_identity, &binding_commitment),
        Some(2),
        "the un-anchored Hub must not have signed serial 2 a second time"
    );

    // And the Hub must not report itself clean while it carries the latch,
    // even with no witness to measure - the evidence document is `None` here,
    // so the count has to come from durable state or it comes from nowhere.
    let readiness = unanchored.mainnet_readiness().await;
    assert!(
        readiness.rollback_anchor.is_none(),
        "no witness is configured, so there is no live evidence to publish"
    );
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "rollback_anchor_channels_latched_in_refusal"),
        "a Hub carrying an unread latch must not publish a clean blocker list, got {:?}",
        readiness.blockers
    );
    assert!(!readiness.payments_enabled);

    // THE CONTROL. A Hub that never had an anchor has no latches, so nothing
    // above may touch it. If this fails, the fix turned into a blanket refusal.
    let never_anchored_directory = tempfile::tempdir().unwrap();
    let (control_left, control_bundle) = signed_bundle(
        "rollback-anchor-never-anchored-left",
        &hub_account,
        &contract,
    );
    let (control_node_url, control_node) = spawn_node(control_bundle.binding.clone()).await;
    let never_anchored = build_hub(
        &never_anchored_directory.path().join("hub-state.json"),
        &hub_account,
        &control_node_url,
    );
    never_anchored
        .activate_hvm_registry_recovery(control_bundle.clone(), 5_000, 1)
        .await
        .unwrap();
    let control_payment = left_signed_payment(
        &control_left,
        &control_bundle,
        "never-anchored-payment-1",
        now_unix(),
    );
    let control_signed = never_anchored
        .cosign_hvm_registry_payment(control_payment, now_unix())
        .await
        .expect("a Hub that never had an anchor holds no latches and must be unaffected");
    assert_eq!(control_signed.bill.serial, 2);
    assert!(
        control_signed.anchor_receipts.is_empty(),
        "a Hub that never had an anchor has no receipt to attach, and says so by attaching          none rather than by omitting the field"
    );
    let control_readiness = never_anchored.mainnet_readiness().await;
    assert!(
        !control_readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "rollback_anchor_channels_latched_in_refusal"),
        "a Hub with no latches must gain no latch blocker, got {:?}",
        control_readiness.blockers
    );

    control_node.abort();
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
            None,
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
            None,
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

/// ADR-001 Option B, built literally.
///
/// Three distinct keys, a valid attestation, a live witness answering signed
/// status - and its durable store sitting in the very directory that gets
/// restored with the Hub's state. Every equality check in `key_custody_distinct`
/// passes, because nothing here is equal to anything; the witness shares the
/// filesystem, the backup set and the restore with the state it is supposed to
/// guard, which is the option this design rejected.
///
/// The guard cannot prove the witness is outside the Hub's failure domain -
/// nothing in this protocol can - so what it must do instead is make this
/// configuration impossible to reach by accident and impossible to reach
/// silently.
#[tokio::test]
async fn a_witness_store_in_the_hub_state_tree_is_detected_published_and_refused_on_mainnet() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-colocated-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x43; 20])).to_readable();
    let (_left, bundle) = signed_bundle("rollback-anchor-colocated-left", &hub_account, &contract);
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;

    // One directory. The Hub state, the witness store, and by implication one
    // backup set and one restore.
    let shared = tempfile::tempdir().unwrap();
    let state_path = shared.path().join("hub-state.json");
    let witness = spawn_witness_at(
        "colocated",
        None,
        shared.path().join("witness-anchor-log.jsonl"),
    )
    .await;

    // Off the mainnet profiles this is allowed - local development and the
    // Local Pilot are legitimate and needed - but never silently.
    let hub = build_hub(&state_path, &hub_account, &node_url)
        .with_rollback_anchor(witness.config(&hub_identity, None))
        .expect("a non-mainnet profile must still start, so the pilot keeps working");
    hub.run_rollback_anchor_startup_probe().await.unwrap();
    let evidence = hub
        .rollback_anchor_evidence()
        .await
        .expect("a live witness must produce verified evidence");
    assert!(
        evidence.witness_store_in_hub_state_tree,
        "a witness durable store sitting in this Hub's own state tree must be seen"
    );
    assert!(
        evidence.witness_co_located,
        "and it must be published as co-located rather than as a bare true flag"
    );

    let readiness = hub.mainnet_readiness().await;
    assert!(
        readiness
            .limitations
            .iter()
            .any(|limitation| limitation.contains("co-located")),
        "the weak configuration must be stated in the document a wallet reads, got {:?}",
        readiness.limitations
    );

    // The two signals are independent. A witness whose store is somewhere else
    // entirely is still on loopback, so it is still co-located - but the store
    // half must now read false, or it is not measuring anything.
    let elsewhere = spawn_witness("colocated-control").await;
    let control_directory = tempfile::tempdir().unwrap();
    let control = build_hub(
        &control_directory.path().join("hub-state.json"),
        &hub_account,
        &node_url,
    )
    .with_rollback_anchor(elsewhere.config(&hub_identity, None))
    .unwrap();
    control.run_rollback_anchor_startup_probe().await.unwrap();
    let control_evidence = control.rollback_anchor_evidence().await.unwrap();
    assert!(
        !control_evidence.witness_store_in_hub_state_tree,
        "a store outside the Hub's state tree must not be reported as inside it"
    );
    assert!(
        control_evidence.witness_co_located,
        "loopback alone is still co-location, on its own signal"
    );

    // On a mainnet profile it is refused outright. Deliberately proven with an
    // endpoint that is *not* loopback and *is* HTTPS, so hard refusal 1 cannot
    // fire and this refusal has to come from the store check on its own.
    let external = "https://witness.example.org";
    let refusal = RollbackAnchorClient::connect(
        witness.config(&hub_identity, Some(external)),
        &hub_identity,
        &hub_identity,
        "mainnet-pilot",
        Some(&state_path),
    )
    .err()
    .expect("a mainnet Hub must not start with a witness store in its own backup set")
    .to_string();
    assert!(
        refusal.contains("rollback_anchor_witness_is_not_external"),
        "the refusal must name the identifier the recovery document indexes, got: {refusal}"
    );
    assert!(
        refusal.contains("witness-anchor-log.jsonl"),
        "the refusal must name the file the operator has to move, got: {refusal}"
    );

    // Same external endpoint, same keys, same attestation, clean directory:
    // the mainnet profile must accept it, or the check is refusing the wrong
    // thing.
    RollbackAnchorClient::connect(
        witness.config(&hub_identity, Some(external)),
        &hub_identity,
        &hub_identity,
        "mainnet-pilot",
        Some(&control_directory.path().join("hub-state.json")),
    )
    .expect("a witness outside the Hub's state tree over HTTPS is the configuration this is for");

    node.abort();
    witness.handle.abort();
    elsewhere.handle.abort();
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
        // Published on the readiness document rather than raised on the
        // signing path, but an operator meets it the same way and has to be
        // able to look it up the same way.
        l2_fast_pay_hub::readiness::ROLLBACK_ANCHOR_LATCHED_BLOCKER,
        l2_fast_pay_hub::readiness::ROLLBACK_ANCHOR_IDENTITY_UNREADABLE_BLOCKER,
    ] {
        assert!(
            document.contains(identifier),
            "{identifier} is printed by the Hub but has no entry in the recovery document"
        );
    }

    // The readiness text tells an operator whose witness was replaced to read
    // this document, and names the route it should find there. A route the Hub
    // points at and the document does not mention is a dead end at the exact
    // moment an operator has run out of other options.
    assert!(
        document.contains("anchor-continuity"),
        "the continuity route the readiness document points operators at must be documented here"
    );

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

/// Can a Hub that has already anchored ever gain a **new** witness?
///
/// The proposed answer was adoption: the joining witness joins at an explicit
/// baseline - the Hub's current position at the moment of joining - co-signed
/// by the joining witness operator's offline authorisation key, so that the
/// Hub cannot mint itself a convenient history.
///
/// This test is the reason that answer does not hold. It runs the same joining
/// witness against two Hubs that differ only in whether their operator is
/// honest, and shows that nothing available to either the Hub or the joining
/// witness separates them:
///
/// 1. An **honest** Hub, fully current at serial 2, that simply wants a second
///    witness. This is the multi-witness case, and it is refused.
/// 2. A **rolled-back** Hub, restored to the snapshot taken before that bill,
///    pointing at a fresh witness to escape the incumbent that holds serial 2.
///    This is exactly the move `ROLLBACK-ANCHOR-RECOVERY.md` section 9 item 4
///    forbids by name.
///
/// Both are refused, by the same check, with character-identical words. That
/// is not a bug in the refusal - it is the whole finding. Any change that lets
/// case 1 through by consulting a credential from the joining side lets case 2
/// through with it, because the joining witness's offline key signs a number
/// the Hub handed it and has no independent knowledge of the Hub's history.
///
/// The test also walks the three gates in the order they actually fire, which
/// is not the order the defect report assumed: the instance pin
/// (`client.rs`, `verify_status`) fires first, the global counter second, and
/// only then the per-channel amnesia arm in `state/rollback_anchor.rs`. The
/// middle gate is the one that cannot be rescued by any counterparty, because
/// the global counter exists precisely to catch a restore that lost an entire
/// channel - and a channel the Hub has forgotten has no counterparty in the
/// Hub's view to ask.
#[tokio::test]
async fn a_joining_witness_cannot_be_told_apart_from_an_amnesiac_one() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-adopt-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x44; 20])).to_readable();
    let (left, bundle) = signed_bundle("rollback-anchor-adopt-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let incumbent = spawn_witness("adopt-incumbent").await;

    let live_directory = tempfile::tempdir().unwrap();
    let backup_directory = tempfile::tempdir().unwrap();
    let state_path = live_directory.path().join("hub-state.json");

    {
        let hub = build_hub(&state_path, &hub_account, &node_url)
            .with_rollback_anchor(incumbent.config(&hub_identity, None))
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
            .await
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();

        // THE BACKUP. Taken here, after the Hub has pinned the incumbent and
        // before it signs anything, exactly as an operator snapshot would be.
        copy_state_directory(live_directory.path(), backup_directory.path());

        let payment = left_signed_payment(&left, &bundle, "adopt-payment-1", now_unix());
        assert_eq!(
            hub.cosign_hvm_registry_payment(payment, now_unix())
                .await
                .unwrap()
                .bill
                .serial,
            2
        );
    }
    assert_eq!(
        incumbent.observed_serial(&hub_identity, &binding_commitment),
        Some(2),
        "the incumbent witness holds the true position"
    );

    // The joining witness. A fresh durable store, a counter at zero, and no
    // record of this Hub at all.
    let joining = spawn_witness("adopt-joining").await;
    assert_eq!(
        joining.observed_serial(&hub_identity, &binding_commitment),
        None
    );

    // The credential the proposed design rests on: the joining witness
    // operator's OFFLINE authorisation key, signing a statement bound to
    // (witness_id, witness_instance_id, hub_identity). This is the machinery
    // at `protocol.rs` `WitnessDeploymentAttestationV1`, verified in
    // `client.rs` `RollbackAnchorClient::connect`. It is valid, and it is the
    // strongest thing the joining side can produce.
    let credential = joining.config(&hub_identity, None).attestation;
    credential
        .verify_against_pinned_key(joining.authorisation.readable())
        .expect("the joining witness operator's offline key signs a valid statement");

    // Case 1: the HONEST Hub, current at serial 2, adding a second witness.
    let honest = build_hub(&state_path, &hub_account, &node_url)
        .with_rollback_anchor(joining.config(&hub_identity, None))
        .unwrap();
    let honest_refusal = honest
        .run_rollback_anchor_startup_probe()
        .await
        .expect_err("a Hub that has anchored cannot currently gain a witness")
        .to_string();
    drop(honest);

    // Case 2: the ROLLED-BACK Hub, restored to the pre-payment snapshot, which
    // has forgotten the bill at serial 2 entirely, pointing at the same fresh
    // witness to get past the incumbent.
    let restored_state = backup_directory.path().join("hub-state.json");
    let rolled_back = build_hub(&restored_state, &hub_account, &node_url)
        .with_rollback_anchor(joining.config(&hub_identity, None))
        .unwrap();
    let rolled_back_refusal = rolled_back
        .run_rollback_anchor_startup_probe()
        .await
        .expect_err("a rolled-back Hub must not escape by changing witness")
        .to_string();

    // THE FINDING. Same check, same words, two opposite intentions.
    assert_eq!(
        honest_refusal, rolled_back_refusal,
        "an honest join and a rollback escape are indistinguishable at the point of refusal"
    );
    assert!(
        honest_refusal.contains("rollback_anchor_witness_instance_changed"),
        "the first gate a joining witness trips is the instance pin, not the amnesia arm, got: \
         {honest_refusal}"
    );

    // Gate 2. Waiving the instance pin - which any adoption must do, since a
    // joining witness is by definition a different durable store - exposes the
    // global counter, and this is the gate no counterparty can answer: it
    // exists to catch a restore that lost an entire channel, and a forgotten
    // channel has no counterparty in the Hub's view to be asked.
    let client = RollbackAnchorClient::connect(
        joining.config(&hub_identity, None),
        &hub_identity,
        &hub_identity,
        "local-pilot",
        None,
    )
    .unwrap();
    let counter_refusal = client
        .probe(
            &RollbackAnchorPin {
                witness_id: String::new(),
                witness_instance_id: String::new(),
                highest_counter_value: 1,
                updated_unix: now_unix(),
            },
            now_unix(),
        )
        .await
        .expect_err("a witness at counter zero is behind a Hub that has recorded one")
        .to_string();
    assert!(
        counter_refusal.contains("rollback_anchor_witness_behind_hub"),
        "got: {counter_refusal}"
    );

    // Gate 3. Waiving the counter too - a fully adopted pin - and the joining
    // witness answers happily, holding nothing. That empty answer, against a
    // Hub whose anchor record reaches serial 2, is the exact input to the
    // amnesia arm in `state/rollback_anchor.rs`. A fresh witness agrees with
    // everything, which is what makes it worthless rather than what makes it
    // wrong.
    let adopted = client
        .probe(&RollbackAnchorPin::default(), now_unix())
        .await
        .expect("a fully adopted pin waives both earlier gates");
    assert_eq!(adopted.status.counter_value, 0);
    assert!(
        adopted.status.channel(&binding_commitment).is_none(),
        "the joining witness holds no history for a channel this Hub has anchored to serial 2"
    );

    // And the reason no credential from the joining side can close gate 3: the
    // joining witness operator's offline key certifies who they are and which
    // Hub they serve. It names no ledger position, no serial and no counter,
    // because it cannot - the joining operator has never seen this Hub's
    // history. Extending it with a baseline would only move a number the Hub
    // supplied under a signature from a party the Hub's operator chose.
    let credential_text = serde_json::to_string(&credential).unwrap();
    for absent in ["serial", "counter", "bill_commitment"] {
        assert!(
            !credential_text.contains(absent),
            "the joining witness's offline credential names no position, so it cannot separate an \
             honest join from a rollback escape: {credential_text}"
        );
    }

    // Nothing in any of this moved the incumbent, which still holds the truth.
    assert_eq!(
        incumbent.observed_serial(&hub_identity, &binding_commitment),
        Some(2)
    );

    node.abort();
    incumbent.handle.abort();
    joining.handle.abort();
}

/// A briefly unreachable witness must stop the Hub SIGNING. It must not stop
/// the Hub EXISTING.
///
/// These are two different things and the second one is worse. A Hub that will
/// not start cannot serve a cooperative close, cannot answer
/// `/v1/readiness/mainnet`, and cannot tell the operator which of the
/// identifiers in `ROLLBACK-ANCHOR-RECOVERY.md` section 2 it hit - and under a
/// systemd unit with `Restart=on-failure` it crash-loops, so the operator's
/// instinct to restart it makes things strictly worse while telling them
/// nothing. Section 2 closes by telling the operator that a Hub which "printed
/// nothing and simply will not start" should be treated as
/// `rollback_anchor_witness_unreachable`. That line exists to paper over this
/// defect; this test is what makes it unnecessary.
///
/// Every assertion here is about what the Hub *says* and whether the *process*
/// is usable. The refusal is asserted too, unchanged, because the whole point
/// is that nothing about the signature moved.
#[tokio::test]
async fn an_unreachable_witness_at_startup_refuses_the_signature_and_names_itself_in_readiness() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-boot-unreachable-hub").unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x47; 20])).to_readable();
    let (left, bundle) = signed_bundle(
        "rollback-anchor-boot-unreachable-left",
        &hub_account,
        &contract,
    );
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let witness = spawn_witness("boot-unreachable").await;
    let directory = tempfile::tempdir().unwrap();

    // Pinned to a live witness's keys, pointed at a port that answers nothing.
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

    // THE DEFECT. The Hub is up. Ask it what is wrong, the way an operator or a
    // monitoring system would, and it must answer by name. Before this, the
    // only way to learn any of it was the exit status of a process that had
    // already gone.
    let readiness = hub.mainnet_readiness().await;
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "rollback_anchor_witness_unreachable"),
        "a running Hub that is refusing to sign must publish the identifier that selects the \
         operator procedure, got {:?}",
        readiness.blockers
    );
    assert!(
        !readiness.payments_enabled,
        "and it must not advertise payments it will refuse"
    );
    assert!(
        readiness.limitations.iter().any(|limitation| {
            limitation.contains("rollback_anchor_witness_unreachable")
                && limitation.contains("ROLLBACK-ANCHOR-RECOVERY.md")
        }),
        "in words as well as in an identifier, pointing at the procedure, got {:?}",
        readiness.limitations
    );

    // Close must NOT be taken down with it. A Hub kept alive to serve a
    // cooperative close is most of the reason for keeping it alive at all, and
    // an anchor that cannot answer must not trap a channel that wants to leave.
    assert!(
        !readiness
            .close_blockers
            .iter()
            .any(|blocker| blocker == "rollback_anchor_witness_unreachable"),
        "an unreachable anchor must not block cooperative close, got {:?}",
        readiness.close_blockers
    );

    // AND THE PART THAT MUST NOT HAVE MOVED. Not one bill more is signed than
    // was signed before any of this. The probe has not agreed, so the signing
    // path refuses, exactly as it did.
    hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
        .await
        .unwrap();
    let payment = left_signed_payment(&left, &bundle, "boot-unreachable-payment", now_unix());
    let error = hub
        .cosign_hvm_registry_payment(payment, now_unix())
        .await
        .expect_err("a Hub whose probe has not agreed must not sign, running or not")
        .to_string();
    assert!(
        error.contains("startup probe has not agreed"),
        "got: {error}"
    );

    node.abort();
    witness.handle.abort();
}

/// The boot posture: what a startup probe means for the process, and what it
/// still means for a signature.
///
/// Both directions, because a blocker that is always published is a constant
/// rather than a measurement: a witness that answers clears it.
#[tokio::test]
async fn the_boot_posture_refuses_the_signature_without_refusing_the_process() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-boot-posture-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x48; 20])).to_readable();
    let (_left, bundle) =
        signed_bundle("rollback-anchor-boot-posture-left", &hub_account, &contract);
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let witness = spawn_witness("boot-posture").await;

    // Unreachable: refused, named, and explicitly not condemning - which is the
    // distinction `refusal_condemns_the_channel` already draws, and what lets
    // the Hub keep asking instead of needing a human.
    let down_directory = tempfile::tempdir().unwrap();
    let down = build_hub(
        &down_directory.path().join("hub-state.json"),
        &hub_account,
        &node_url,
    )
    .with_rollback_anchor(witness.config(&hub_identity, Some("http://127.0.0.1:1")))
    .unwrap();
    let posture = down.run_rollback_anchor_startup_probe_at_boot().await;
    assert!(
        !posture.agreed,
        "an unreachable witness proves nothing, so nothing may sign"
    );
    assert_eq!(
        posture.refusal_identifier,
        Some("rollback_anchor_witness_unreachable")
    );
    assert!(
        !posture.condemning,
        "silence is not a refusal from the witness and must not condemn a channel"
    );
    assert!(
        posture
            .refusal
            .as_deref()
            .is_some_and(|refusal| refusal.contains("An unreachable oracle is not evidence")),
        "the log line must say why silence is not permission, got {:?}",
        posture.refusal
    );
    assert_eq!(
        down.rollback_anchor_probe_refusal(),
        Some("rollback_anchor_witness_unreachable")
    );

    // Reachable: agreed, nothing published, nothing blocked.
    let up_directory = tempfile::tempdir().unwrap();
    let up = build_hub(
        &up_directory.path().join("hub-state.json"),
        &hub_account,
        &node_url,
    )
    .with_rollback_anchor(witness.config(&hub_identity, None))
    .unwrap();
    let posture = up.run_rollback_anchor_startup_probe_at_boot().await;
    assert!(posture.agreed, "a live witness that agrees must agree");
    assert_eq!(posture.refusal_identifier, None);
    assert_eq!(up.rollback_anchor_probe_refusal(), None);
    let readiness = up.mainnet_readiness().await;
    assert!(
        !readiness
            .blockers
            .iter()
            .any(|blocker| blocker.starts_with("rollback_anchor_witness")),
        "a Hub whose probe agreed publishes no anchor refusal, got {:?}",
        readiness.blockers
    );

    node.abort();
    witness.handle.abort();
}

/// The receipt has to reach the wallet, over HTTP, attached to the bill.
///
/// The overlap rule the counterparty enforces - "every new bill must carry a
/// receipt from at least one witness that receipted my last accepted bill" -
/// is worth nothing if the receipt stops at the Hub's process boundary. A
/// field that exists in Rust and never reaches the wire is exactly the bug
/// this design cannot afford, because the failure is silent: the wallet sees
/// no receipts, concludes the Hub has no anchor, and the ratchet resets to
/// whatever the Hub declares.
///
/// So this test is deliberately not a unit test on the state layer. It stands
/// up the real Hub router, posts a real payment over real HTTP, and reads the
/// bytes that come back. Every hop between `reserve_rollback_anchor` and the
/// response body is under test at once.
#[tokio::test]
async fn a_cosigned_bill_carries_its_witness_receipt_all_the_way_onto_the_wire() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-wire-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x47; 20])).to_readable();
    let (left, bundle) = signed_bundle("rollback-anchor-wire-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let witness = spawn_witness("wire").await;
    let directory = tempfile::tempdir().unwrap();

    let hub = build_hub(
        &directory.path().join("hub-state.json"),
        &hub_account,
        &node_url,
    )
    .with_rollback_anchor(witness.config(&hub_identity, None))
    .unwrap();
    hub.run_rollback_anchor_startup_probe().await.unwrap();
    hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
        .await
        .unwrap();
    hub.run_rollback_anchor_startup_probe().await.unwrap();

    let hub = Arc::new(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = hub.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, l2_fast_pay_hub::build_router(served)).await;
    });

    let payment = left_signed_payment(&left, &bundle, "wire-payment-1", now_unix());
    // The commitment the receipt binds to is the PAYER-SIGNED, HUB-UNSIGNED
    // bill, because the Hub fills `hub_signature_hex` after the reservation.
    // This is the commitment a wallet holds durably in its own request.
    let proposed_commitment = payment.proposed_bill.commitment().unwrap();

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v2/hvm-registry/payment"))
        .json(&payment)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "an honest bill against a live witness must be co-signed"
    );
    let body: Value = response.json().await.unwrap();

    // 1. The bill is still there, unchanged in meaning.
    let bill: HvmRegistryBillV2 = serde_json::from_value(
        body.get("bill")
            .cloned()
            .expect("the co-signed response must carry the bill under `bill`"),
    )
    .expect("the `bill` field must deserialise as the registry bill");
    assert_eq!(bill.serial, 2);
    assert!(!bill.hub_signature_hex.is_empty());

    // 2. The receipts are there, on the wire, not merely in Rust.
    let receipts = body
        .get("anchor_receipts")
        .and_then(Value::as_array)
        .cloned()
        .expect("the co-signed response must carry `anchor_receipts`");
    assert_eq!(
        receipts.len(),
        1,
        "a Hub with one configured witness must attach exactly its one receipt, got {receipts:?}"
    );

    // 3. The receipt is cryptographically real. A Hub that could satisfy the
    //    overlap rule by naming a witness would have defeated it in one line,
    //    so the wallet checks the signature and so does this test.
    let signed: SignedHubWitnessReceiptV1 = serde_json::from_value(receipts[0].clone())
        .expect("the attached receipt must deserialise as SignedHubWitnessReceiptV1");
    signed
        .verify_against_pinned_key(witness.service.receipt_address())
        .expect("the attached receipt must verify against the witness's real signing key");

    // 4. It is bound to this exact bill, this exact channel and this exact Hub.
    assert_eq!(signed.receipt.proposed_bill_commitment, proposed_commitment);
    assert_eq!(signed.receipt.serial, 2);
    assert_eq!(signed.receipt.binding_commitment, binding_commitment);
    assert_eq!(signed.receipt.hub_identity, hub_identity);
    assert_eq!(
        signed.receipt.witness_instance_id,
        witness.instance_id(&hub_identity),
        "the receipt must name the witness's durable store, which is the pair key the \
         counterparty ratchets on"
    );

    // 5. The same receipt survives the crash window: a wallet that died between
    //    the Hub signing and its own persist must be able to fetch the head and
    //    its receipts back, or the channel is stuck with no honest way out.
    let status: Value = reqwest::Client::new()
        .get(format!(
            "http://{address}/v2/hvm-registry/channel/{binding_commitment}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let latest = status
        .get("latest_anchor_receipts")
        .and_then(Value::as_array)
        .cloned()
        .expect("the channel status must carry `latest_anchor_receipts` beside the head bill");
    assert_eq!(latest.len(), 1, "got {latest:?}");
    let stored: SignedHubWitnessReceiptV1 = serde_json::from_value(latest[0].clone()).unwrap();
    assert_eq!(stored, signed, "the stored receipt must be the one served");

    server.abort();
    node.abort();
    witness.handle.abort();
}

/// LOSING THE ONE WITNESS MUST NOT MEAN LOSING THE HUB.
///
/// A Hub has exactly one witness (ADR-001, settled). Replace that witness's
/// durable store - the witness operator rebuilds it, or the Hub's operator has
/// no choice but to move to a different witness - and the pin no longer
/// matches. The startup probe refuses `rollback_anchor_witness_instance_changed`
/// and can never agree again, so the Hub co-signs nothing, forever. That part
/// is correct and this test asserts it stays correct: a fresh witness store
/// agrees with everything, which is amnesia rather than agreement, and no
/// Hub-side check can tell an honest replacement apart from a rolled-back Hub
/// shopping for a witness with no memory.
///
/// What was missing is the exit. The break was legible only as an absent
/// blocker; the payer - the one party whose memory the Hub cannot reach and
/// therefore the only one who can judge this - was told nothing at all; and the
/// only thing an operator could actually *do* was delete the five
/// `--rollback-witness-*` flags, which is the anchor's failure mode being "turn
/// it off".
///
/// So, in order: the process starts, the signature is still refused, the break
/// is named in the readiness document with both store identities, and the Hub
/// serves a declaration - this channel's existing head, same serial and same
/// bill commitment, re-anchored under the witness answering now. **Nothing new
/// is signed to produce it.** A Hub that had to sign in order to prove itself
/// would be signing under a witness it had just chosen, which is the circle.
#[tokio::test]
async fn a_replaced_witness_starts_publishes_the_break_and_declares_the_head_without_signing() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-continuity-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x49; 20])).to_readable();
    let (left, bundle) = signed_bundle("rollback-anchor-continuity-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let incumbent = spawn_witness("continuity-incumbent").await;

    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");

    // The head the payer will end up holding: one real co-signed bill at serial
    // 2, receipted by the incumbent witness.
    let head_commitment = {
        let hub = build_hub(&state_path, &hub_account, &node_url)
            .with_rollback_anchor(incumbent.config(&hub_identity, None))
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
            .await
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        let payment = left_signed_payment(&left, &bundle, "continuity-payment-1", now_unix());
        // The commitment the receipt binds to, and the value the payer records
        // as its accepted head: the payer-signed, Hub-UNSIGNED bill.
        let commitment = payment.proposed_bill.commitment().unwrap();
        assert_eq!(
            hub.cosign_hvm_registry_payment(payment, now_unix())
                .await
                .unwrap()
                .bill
                .serial,
            2
        );
        commitment
    };
    assert_eq!(
        incumbent.observed_serial(&hub_identity, &binding_commitment),
        Some(2)
    );

    // THE BREAK. The incumbent's store is gone; the operator is now configured
    // against a different witness, correctly attested to this Hub. Everything
    // about this configuration is valid. It is simply not the store this Hub
    // pinned.
    let replacement = spawn_witness("continuity-replacement").await;

    // 1. IT STARTS. Attaching the anchor and running the boot probe both
    //    complete; there is no `?` out of either that takes the process with
    //    it. A Hub that will not start cannot close a channel cooperatively,
    //    cannot answer readiness, and cannot tell anyone why - and under
    //    `Restart=on-failure` the operator's instinct to restart it is the
    //    first thing the recovery document forbids.
    let hub = build_hub(&state_path, &hub_account, &node_url)
        .with_rollback_anchor(replacement.config(&hub_identity, None))
        .expect("a Hub whose witness was replaced must still be constructible");
    let posture = hub.run_rollback_anchor_startup_probe_at_boot().await;
    assert!(
        !posture.agreed,
        "a replacement witness store agrees with everything and proves nothing"
    );
    assert_eq!(
        posture.refusal_identifier,
        Some("rollback_anchor_witness_instance_changed")
    );
    assert!(
        posture.condemning,
        "a changed witness store does not clear by waiting and must not be retried in a loop"
    );

    // 2. IT DOES NOT SIGN. Untouched, and asserted before anything else runs,
    //    so no later step can be read as having enabled it.
    let head_bill = hub
        .hvm_registry_channel_status(&binding_commitment)
        .unwrap()
        .latest_fully_signed_bill;
    assert_eq!(head_bill.serial, 2);
    let refused = left_signed_payment_on_head(
        &left,
        &bundle,
        &head_bill,
        "continuity-payment-2",
        now_unix(),
    );
    let error = hub
        .cosign_hvm_registry_payment(refused, now_unix())
        .await
        .expect_err("a Hub whose probe has not agreed must not sign")
        .to_string();
    assert!(
        error.contains("startup probe has not agreed"),
        "got: {error}"
    );

    // 3. IT PUBLISHES THE BREAK, by name and with both store identities, so it
    //    is visible from outside rather than inferable from an absent blocker.
    //    Read off the serialised document, because that is what an operator and
    //    a monitoring system actually receive.
    let readiness = hub.mainnet_readiness().await;
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "rollback_anchor_witness_instance_changed"),
        "got {:?}",
        readiness.blockers
    );
    assert!(!readiness.payments_enabled);
    assert!(
        !readiness
            .close_blockers
            .iter()
            .any(|blocker| blocker.starts_with("rollback_anchor_witness")),
        "a broken anchor must never trap a channel that wants to close, got {:?}",
        readiness.close_blockers
    );
    let document = serde_json::to_value(&readiness).unwrap();
    let published = document
        .get("rollback_anchor_witness_identity_break")
        .cloned()
        .expect(
            "a Hub refusing forever because its witness was replaced must say so in the readiness \
             document, not leave it to be inferred",
        );
    assert_eq!(
        published
            .get("pinned_witness_instance_id")
            .and_then(Value::as_str),
        Some(incumbent.instance_id(&hub_identity).as_str()),
        "the break must name the store this Hub pinned, got {published:?}"
    );
    assert_eq!(
        published
            .get("attested_witness_instance_id")
            .and_then(Value::as_str),
        Some(replacement.instance_id(&hub_identity).as_str()),
        "and the store it is configured with now, got {published:?}"
    );
    assert!(
        readiness.limitations.iter().any(|limitation| {
            limitation.contains("anchor-continuity") && limitation.contains("Nothing new is signed")
        }),
        "and in words, pointing at where the declaration is served, got {:?}",
        readiness.limitations
    );

    // 4. IT SERVES A DECLARATION, over real HTTP, on the running Hub.
    let hub = Arc::new(hub);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = hub.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, l2_fast_pay_hub::build_router(served)).await;
    });
    let url =
        format!("http://{address}/v2/hvm-registry/channel/{binding_commitment}/anchor-continuity");
    let response = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a Hub that is refusing to sign must still be able to tell the payer why"
    );
    let declaration: Value = response.json().await.unwrap();

    // Same serial, same bill commitment. This is the whole safety argument: the
    // ceremony re-anchors a head the payer already holds and mints nothing.
    assert_eq!(
        declaration.get("serial").and_then(Value::as_u64),
        Some(2),
        "got {declaration:?}"
    );
    assert_eq!(
        declaration.get("bill_commitment").and_then(Value::as_str),
        Some(head_commitment.as_str()),
        "the declared commitment must be the payer-signed, Hub-unsigned one the payer recorded"
    );
    let receipts = declaration
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .expect("a declaration re-anchors or it declares nothing");
    assert_eq!(receipts.len(), 1, "one Hub, one witness: got {receipts:?}");
    let signed: SignedHubWitnessReceiptV1 = serde_json::from_value(receipts[0].clone()).unwrap();
    signed
        .verify_against_pinned_key(replacement.service.receipt_address())
        .expect("the re-anchor must be signed by the replacement witness's real key");
    assert_eq!(signed.receipt.serial, 2);
    assert_eq!(signed.receipt.proposed_bill_commitment, head_commitment);
    assert_eq!(signed.receipt.binding_commitment, binding_commitment);
    assert_eq!(
        signed.receipt.witness_instance_id,
        replacement.instance_id(&hub_identity),
        "the receipt must name the replacement's store - that is the half of the pair key the \
         payer's ratchet notices has changed"
    );

    // A second read replays the first declaration rather than minting another.
    // Two payers reading one head must be shown one declaration, and a read
    // must not burn a position on the witness every time.
    let again: Value = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        again.get("receipts"),
        declaration.get("receipts"),
        "a repeated read must replay the same declaration"
    );

    // AND THE PART THAT MUST NOT HAVE MOVED. The Hub is exactly as unable to
    // sign as it was before it declared anything, and the incumbent - which
    // still holds the truth about this channel - was not touched by any of it.
    // Asserted on the exact bit `reserve_rollback_anchor` reads before any
    // signature, rather than on a second payment attempt: the payment path is
    // already unavailable for its own reasons by now, and this is the gate
    // itself. Re-running the probe re-derives it from the live witness.
    let after = hub.run_rollback_anchor_startup_probe_at_boot().await;
    assert!(
        !after.agreed,
        "declaring must not adopt the replacement witness or set the bit that permits signing"
    );
    assert_eq!(
        after.refusal_identifier,
        Some("rollback_anchor_witness_instance_changed"),
        "and the Hub must still be refusing for the same reason it was before"
    );
    assert!(
        serde_json::to_value(&hub.mainnet_readiness().await)
            .unwrap()
            .get("rollback_anchor_witness_identity_break")
            .is_some(),
        "the break is not cleared by declaring it"
    );
    assert_eq!(
        incumbent.observed_serial(&hub_identity, &binding_commitment),
        Some(2)
    );

    server.abort();
    node.abort();
    incumbent.handle.abort();
    replacement.handle.abort();
}

/// The other way a Hub loses its witness, and the one that actually happens:
/// the witness box dies and is rebuilt **from the witness's own backup**, a few
/// reservations behind.
///
/// This is deliberately *not* the continuity case, and the difference is the
/// point. A restored store keeps its identity - `WitnessStore::open` takes the
/// instance id out of the replayed header and mints a fresh one only when there
/// is no header - so the pin still matches, nothing about the Hub's witness
/// *identity* changed, and there is no witness set for a payer to adjudicate.
/// What changed is that the anchor has forgotten positions this Hub already
/// signed, which is exactly the shape of a witness that was reset for an
/// attacker's benefit. The Hub cannot tell those apart and must not try.
///
/// So this test pins the honest answer rather than a hoped-for one:
///
/// * the Hub **starts**, refuses silently, and names the refusal
///   `rollback_anchor_witness_behind_hub` - the identifier the recovery document
///   routes to Procedure B - rather than the transient unreachable one;
/// * it publishes **no** `rollback_anchor_witness_identity_break`, because none
///   happened, and blurring the two would tell an operator to go looking for a
///   replacement witness that does not exist;
/// * the continuity declaration **refuses**, by name. Serving one here would
///   mean asking a witness that has gone backwards to re-anchor a head it has
///   forgotten, which is `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md`'s "do not
///   resynchronise the witness to the Hub" performed by the Hub itself;
/// * cooperative close is untouched, which is the whole exit that remains.
///
/// There is no way back to signing from here and this test does not pretend
/// there is. Procedure B step 4 says so out loud: the rebuild-to-position
/// mechanism does not exist.
#[tokio::test]
async fn a_witness_restored_from_its_own_backup_is_refused_and_has_no_declaration_to_serve() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-restored-witness-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x4a; 20])).to_readable();
    let (left, bundle) = signed_bundle("rollback-anchor-restored-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;

    // The witness store lives in its own directory, not in the Hub's state
    // tree - co-location is a separate refusal with its own test.
    let witness_directory = tempfile::tempdir().unwrap();
    let store_path = witness_directory.path().join("witness-log.jsonl");
    let backup_path = witness_directory.path().join("witness-log.backup.jsonl");
    let witness = spawn_witness_at("restored-witness", None, store_path.clone()).await;
    let instance_id = witness.instance_id(&hub_identity);

    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");

    {
        let hub = build_hub(&state_path, &hub_account, &node_url)
            .with_rollback_anchor(witness.config(&hub_identity, None))
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
            .await
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();

        // THE BACKUP, taken here: a real backup of the witness's own store,
        // from before the reservation it is about to lose.
        std::fs::copy(&store_path, &backup_path).unwrap();

        let payment = left_signed_payment(&left, &bundle, "restored-payment-1", now_unix());
        assert_eq!(
            hub.cosign_hvm_registry_payment(payment, now_unix())
                .await
                .unwrap()
                .bill
                .serial,
            2
        );
    }
    assert_eq!(
        witness.observed_serial(&hub_identity, &binding_commitment),
        Some(2)
    );

    // THE INCIDENT. The witness box is lost and rebuilt from that backup, under
    // the same operator, the same signing key and - because the store header is
    // replayed rather than re-minted - the same durable identity.
    witness.handle.abort();
    std::fs::copy(&backup_path, &store_path).unwrap();
    let restored = spawn_witness_at("restored-witness", None, store_path.clone()).await;
    assert_eq!(
        restored.instance_id(&hub_identity),
        instance_id,
        "a store restored from its own backup keeps its identity - that is what makes this case \
         different from a replacement, and it is why the continuity path does not apply"
    );
    assert_eq!(
        restored.observed_serial(&hub_identity, &binding_commitment),
        None,
        "and it has forgotten the position this Hub signed against it"
    );

    // 1. IT STARTS, and names the permanent condition rather than a transient
    //    one. `condemning` is what stops the boot path retrying it in a loop.
    let hub = build_hub(&state_path, &hub_account, &node_url)
        .with_rollback_anchor(restored.config(&hub_identity, None))
        .expect("a Hub whose witness lost state must still be constructible");
    let posture = hub.run_rollback_anchor_startup_probe_at_boot().await;
    assert!(!posture.agreed);
    assert_eq!(
        posture.refusal_identifier,
        Some("rollback_anchor_witness_behind_hub"),
        "got {posture:?}"
    );
    assert!(posture.condemning);

    // 2. IT DOES NOT SIGN.
    let head_bill = hub
        .hvm_registry_channel_status(&binding_commitment)
        .unwrap()
        .latest_fully_signed_bill;
    assert_eq!(head_bill.serial, 2);
    let refused =
        left_signed_payment_on_head(&left, &bundle, &head_bill, "restored-payment-2", now_unix());
    let error = hub
        .cosign_hvm_registry_payment(refused, now_unix())
        .await
        .expect_err("a witness that went backwards is not an anchor")
        .to_string();
    assert!(
        error.contains("startup probe has not agreed"),
        "got: {error}"
    );

    // 3. IT PUBLISHES THE RIGHT THING, AND NOT THE WRONG ONE.
    let readiness = hub.mainnet_readiness().await;
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "rollback_anchor_witness_behind_hub"),
        "got {:?}",
        readiness.blockers
    );
    assert!(!readiness.payments_enabled);
    assert!(
        !readiness
            .close_blockers
            .iter()
            .any(|blocker| blocker.starts_with("rollback_anchor_witness")),
        "closing on the head the payer already holds is the only exit left and must stay open, \
         got {:?}",
        readiness.close_blockers
    );
    assert!(
        hub.rollback_anchor_witness_identity_break()
            .unwrap()
            .is_none(),
        "the store identity did not change, and saying it did would send the operator hunting for \
         a replacement witness that does not exist"
    );
    assert!(
        serde_json::to_value(&readiness)
            .unwrap()
            .get("rollback_anchor_witness_identity_break")
            .is_none(),
        "and the document must not carry a break that did not happen"
    );

    // 4. THERE IS NO DECLARATION, and the refusal says why in the operator's
    //    terms. A declaration here would be the Hub resynchronising its own
    //    witness under a ceremony name.
    let declined = hub
        .rollback_anchor_continuity_declaration(&binding_commitment, now_unix())
        .await
        .expect_err("a witness that is behind is not a replacement witness")
        .to_string();
    assert!(
        declined.contains("is the witness it pinned"),
        "got: {declined}"
    );

    node.abort();
    restored.handle.abort();
}

/// A payment may not claim the reservation namespace the continuity ceremony
/// owns.
///
/// Continuity declarations are persisted in the same durable map as ordinary
/// per-payment reservations, keyed by a deterministic id, and a payer picks its
/// own `operation_id`. Nothing else in the system stops the two colliding, so
/// the prefix is refused by name on the signing path. This is the only change
/// this work makes to the path that reaches a key, so it gets a test of its
/// own.
#[tokio::test]
async fn a_payment_cannot_claim_the_continuity_reservation_namespace() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-namespace-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x4a; 20])).to_readable();
    let (left, bundle) = signed_bundle("rollback-anchor-namespace-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let witness = spawn_witness("namespace-witness").await;

    let directory = tempfile::tempdir().unwrap();
    let hub = build_hub(
        &directory.path().join("hub-state.json"),
        &hub_account,
        &node_url,
    )
    .with_rollback_anchor(witness.config(&hub_identity, None))
    .unwrap();
    hub.run_rollback_anchor_startup_probe().await.unwrap();
    hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
        .await
        .unwrap();
    hub.run_rollback_anchor_startup_probe().await.unwrap();

    // The control first, so the refusal below is known to be about the
    // namespace and not about the payment: this Hub is healthy, its probe has
    // agreed, and it co-signs.
    let payment = left_signed_payment(&left, &bundle, "namespace-ordinary", now_unix());
    let head = hub
        .cosign_hvm_registry_payment(payment, now_unix())
        .await
        .expect("an ordinary operation id is unaffected")
        .bill;
    assert_eq!(head.serial, 2);

    // The same Hub, the same channel, the same signer. The only thing wrong
    // with this payment is that its operation id claims the reservation key
    // space the continuity ceremony owns.
    let claim = format!(
        "{}{binding_commitment}/2",
        l2_fast_pay_hub::rollback_anchor::CONTINUITY_REQUEST_ID_PREFIX
    );
    let payment = left_signed_payment_on_head(&left, &bundle, &head, &claim, now_unix());
    let error = hub
        .cosign_hvm_registry_payment(payment, now_unix())
        .await
        .expect_err("the continuity namespace is not a payment's to take")
        .to_string();
    assert!(
        error.contains("is reserved for rollback anchor continuity declarations"),
        "got: {error}"
    );

    node.abort();
    witness.handle.abort();
}

/// A lost send must not be terminal for one channel's declaration, and a
/// replacement witness that is *ahead* of the old pin must not make the
/// declaration impossible to store.
///
/// Two separate defects, reachable together because they are both about the
/// same wrong assumption - that a replacement witness's counter is comparable
/// with the incumbent's.
///
/// 1. The continuity request id is derived from `(binding, serial)`, and on a
///    Hub that will never sign again the serial can never move. So unlike the
///    payment path there is no fresh id to retry under: a request that was
///    persisted and then never reached the witness is replayed at its original
///    counter forever, and once any other channel has taken that position the
///    witness refuses `rollback_anchor_hub_behind_witness` - a *rollback
///    accusation* - at a Hub that did nothing wrong. The re-mint is allowed
///    only when the witness's own refusal proves it holds no record of the id.
///
/// 2. The durable state validator required every stored receipt's counter to
///    sit at or below the pin. A continuity receipt comes from a different
///    store, whose counter is unrelated; when the replacement happened to be
///    ahead, persisting the declaration failed - a hard 500 on every read, for
///    exactly the operator this path exists to rescue.
#[tokio::test]
async fn a_declaration_survives_a_lost_send_and_a_replacement_witness_that_is_ahead() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("rollback-anchor-remint-hub").unwrap();
    let hub_identity = Address::from(*hub_account.address()).to_readable();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x4b; 20])).to_readable();
    let (left, bundle) = signed_bundle("rollback-anchor-remint-left", &hub_account, &contract);
    let binding_commitment = bundle.binding.commitment().unwrap();
    let (node_url, node) = spawn_node(bundle.binding.clone()).await;
    let incumbent = spawn_witness("remint-incumbent").await;

    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");
    let head_commitment = {
        let hub = build_hub(&state_path, &hub_account, &node_url)
            .with_rollback_anchor(incumbent.config(&hub_identity, None))
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 1)
            .await
            .unwrap();
        hub.run_rollback_anchor_startup_probe().await.unwrap();
        let payment = left_signed_payment(&left, &bundle, "remint-payment-1", now_unix());
        let commitment = payment.proposed_bill.commitment().unwrap();
        assert_eq!(
            hub.cosign_hvm_registry_payment(payment, now_unix())
                .await
                .unwrap()
                .bill
                .serial,
            2
        );
        commitment
    };

    // The replacement, put deliberately AHEAD of the pin by serving other
    // channels of the same Hub before this one asks for anything. This is the
    // ordinary case for a witness that was already running - not a contrivance.
    let replacement = spawn_witness("remint-replacement").await;
    for step in 1..=5u64 {
        let now = now_unix();
        let request = HubAnchorRequestV1 {
            request_version: 1,
            request_id: format!("other-channel-{step}"),
            hub_identity: hub_identity.clone(),
            witness_id: replacement.service.witness_id().to_owned(),
            witness_epoch: replacement.service.witness_epoch(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.to_owned(),
            network_instance_id: INSTANCE.to_owned(),
            binding_commitment: hex::encode([u8::try_from(step).unwrap(); 32]),
            channel_id: format!("other-channel-{step}"),
            reuse_version: 0,
            serial: 1,
            previous_bill_commitment: "1a".repeat(32),
            proposed_bill_commitment: "2b".repeat(32),
            counter_value: step,
            hub_journal_sequence: step,
            hub_journal_head_hash: "3c".repeat(32),
            hub_state_commitment: "4d".repeat(32),
            created_at: now,
            expires_at: now + 60,
        };
        let signed = SignedHubAnchorRequestV1::sign(request, &hub_account).unwrap();
        assert!(matches!(
            replacement.service.reserve(&signed, now_unix()).unwrap(),
            HubWitnessAnswerV1::Receipt(_)
        ));
    }

    // A proxy in front of the replacement whose `/anchor` route can be cut. The
    // status route stays up throughout, because that is what a lost send looks
    // like: the Hub probes fine, persists its request, and the reservation
    // never lands.
    let reserve_reaches_the_witness = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (proxy_url, proxy) =
        spawn_witness_proxy(&replacement.url, reserve_reaches_the_witness.clone()).await;

    let hub = build_hub(&state_path, &hub_account, &node_url)
        .with_rollback_anchor(replacement.config(&hub_identity, Some(&proxy_url)))
        .expect("a Hub whose witness was replaced must still be constructible");
    assert!(!hub.run_rollback_anchor_startup_probe_at_boot().await.agreed);

    // THE LOST SEND. The request is persisted; the witness never sees it.
    let error = hub
        .rollback_anchor_continuity_declaration(&binding_commitment, now_unix())
        .await
        .expect_err("the reservation could not be delivered")
        .to_string();
    assert!(
        error.contains("rollback_anchor_witness_unreachable"),
        "got: {error}"
    );

    // Another channel takes the position that was reserved for this one while
    // the send was in flight, so the persisted counter is now stale.
    {
        let now = now_unix();
        let request = HubAnchorRequestV1 {
            request_version: 1,
            request_id: "other-channel-after".to_owned(),
            hub_identity: hub_identity.clone(),
            witness_id: replacement.service.witness_id().to_owned(),
            witness_epoch: replacement.service.witness_epoch(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.to_owned(),
            network_instance_id: INSTANCE.to_owned(),
            binding_commitment: hex::encode([0xfeu8; 32]),
            channel_id: "other-channel-after".to_owned(),
            reuse_version: 0,
            serial: 1,
            previous_bill_commitment: "1a".repeat(32),
            proposed_bill_commitment: "2b".repeat(32),
            counter_value: 6,
            hub_journal_sequence: 6,
            hub_journal_head_hash: "3c".repeat(32),
            hub_state_commitment: "4d".repeat(32),
            created_at: now,
            expires_at: now + 60,
        };
        let signed = SignedHubAnchorRequestV1::sign(request, &hub_account).unwrap();
        assert!(matches!(
            replacement.service.reserve(&signed, now_unix()).unwrap(),
            HubWitnessAnswerV1::Receipt(_)
        ));
    }

    // The witness is reachable again. The declaration must now get through.
    reserve_reaches_the_witness.store(true, std::sync::atomic::Ordering::Release);
    let declaration = hub
        .rollback_anchor_continuity_declaration(&binding_commitment, now_unix())
        .await
        .expect("a lost send must not cost this channel its declaration forever");
    assert_eq!(declaration.serial, 2);
    assert_eq!(declaration.bill_commitment, head_commitment);
    assert_eq!(declaration.receipts.len(), 1);
    let receipt = &declaration.receipts[0].receipt;
    assert_eq!(
        receipt.witness_instance_id,
        replacement.instance_id(&hub_identity)
    );
    assert!(
        receipt.counter_value > 5,
        "the re-anchor takes the replacement's *current* position, got {}",
        receipt.counter_value
    );

    // A second read replays it rather than burning another position on the
    // replacement, and the Hub is exactly as unable to sign as it was.
    let again = hub
        .rollback_anchor_continuity_declaration(&binding_commitment, now_unix())
        .await
        .expect("a second read replays");
    assert_eq!(
        again.receipts[0].receipt.counter_value,
        receipt.counter_value
    );
    let refused = left_signed_payment_on_head(
        &left,
        &bundle,
        &hub.hvm_registry_channel_status(&binding_commitment)
            .unwrap()
            .latest_fully_signed_bill,
        "remint-payment-2",
        now_unix(),
    );
    let error = hub
        .cosign_hvm_registry_payment(refused, now_unix())
        .await
        .expect_err("declaring must never restore signing")
        .to_string();
    assert!(
        error.contains("startup probe has not agreed"),
        "got: {error}"
    );

    proxy.abort();
    node.abort();
    incumbent.handle.abort();
    replacement.handle.abort();
}

/// A witness endpoint whose reservation route can be cut without taking its
/// status route down with it - which is what a send lost in the network looks
/// like from the Hub, and the only state in which a persisted-but-unreceipted
/// continuity request exists.
async fn spawn_witness_proxy(
    upstream: &str,
    reserve_reaches_the_witness: Arc<std::sync::atomic::AtomicBool>,
) -> (String, JoinHandle<()>) {
    use axum::routing::post;

    let status_upstream = format!(
        "{upstream}{}",
        l2_fast_pay_hub::rollback_anchor::ANCHOR_STATUS_PATH
    );
    let reserve_upstream = format!(
        "{upstream}{}",
        l2_fast_pay_hub::rollback_anchor::ANCHOR_RESERVE_PATH
    );
    let app = Router::new()
        .route(
            l2_fast_pay_hub::rollback_anchor::ANCHOR_STATUS_PATH,
            post(move |body: String| {
                let status_upstream = status_upstream.clone();
                async move { forward(&status_upstream, body).await }
            }),
        )
        .route(
            l2_fast_pay_hub::rollback_anchor::ANCHOR_RESERVE_PATH,
            post(move |body: String| {
                let reserve_upstream = reserve_upstream.clone();
                let open = reserve_reaches_the_witness.clone();
                async move {
                    if !open.load(std::sync::atomic::Ordering::Acquire) {
                        return Err(StatusCode::BAD_GATEWAY);
                    }
                    forward(&reserve_upstream, body).await
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

async fn forward(url: &str, body: String) -> Result<axum::response::Response, StatusCode> {
    use axum::response::IntoResponse;

    let response = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = response.text().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok((status, [("content-type", "application/json")], body).into_response())
}
