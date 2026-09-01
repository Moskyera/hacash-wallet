use std::collections::HashMap;
#[cfg(feature = "local-pilot-tools")]
use std::sync::Arc;
#[cfg(feature = "local-pilot-tools")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::extract::Query;
use axum::http::StatusCode;
use axum::routing::get;
#[cfg(feature = "local-pilot-tools")]
use axum::routing::post;
use axum::{Json, Router};
use field::{Address, Serialize as FieldSerialize, Sign};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_channel::{
    HVM_CHANNEL_BILL_SCHEMA, HVM_CHANNEL_BINDING_SCHEMA, HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA,
    HvmChannelBillV1, HvmChannelBindingV1, HvmChannelRecoveryBundleV1,
};
use l2_fast_pay_hub::hvm_ledger::{
    HVM_CHANNEL_STATUS_SCHEMA, HVM_PAYMENT_REQUEST_SCHEMA, HvmPaymentRequestV1,
};
#[cfg(feature = "local-pilot-tools")]
use l2_fast_pay_hub::hvm_watchtower::{
    HVM_LEASE_RENEWAL_REQUEST_SCHEMA, HVM_WATCHTOWER_REQUEST_SCHEMA, HvmLeaseRenewalRequestV1,
    HvmWatchtowerMode, HvmWatchtowerRequestV1,
};
use l2_fast_pay_hub::hvm_watchtower::{
    HvmWatchtowerDecision, decide_watchtower_action, recovery_required_reason,
};
use l2_fast_pay_hub::node::{
    HPAY_CHANNEL_EXIT_ACTION_KINDS, HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
    HPAY_CHANNEL_EXIT_CONTRACT_NAME, HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA,
    HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN, HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
    HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT, HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA,
};
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use vm::ContractAddress;

const HPAY_LOCAL_PILOT_NETWORK_KIND: &str = "local_pilot_v1";
const HPAY_LOCAL_PILOT_PROFILE_ID: &str = "hpay-local-pilot-chain-v1";
const HPAY_LOCAL_PILOT_BLOCK_ONE_HASH: &str =
    "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29";
const HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID: &str =
    "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3";

fn secret_hex(account: &Account) -> String {
    hex::encode(account.secret_key().serialize())
}

fn storage_entry(value: Value) -> Value {
    json!({
        "value": value,
        "live_blocks": 10_000,
        "recover_blocks": 20_000,
        "active": true,
        "recoverable": false
    })
}

fn signed_bundle() -> (Account, HvmChannelRecoveryBundleV1) {
    let left = Account::create_by("hpay-durable-activation-left").unwrap();
    let right = Account::create_by("hpay-durable-activation-right").unwrap();
    let binding = HvmChannelBindingV1 {
        schema: HVM_CHANNEL_BINDING_SCHEMA.to_owned(),
        settlement_profile: HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.to_owned(),
        network_mode: "testnet".to_owned(),
        chain_id: 7,
        network_instance_id: HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID.to_owned(),
        contract_address: ContractAddress::from_unchecked(Address::create_contract([7; 20]))
            .to_readable(),
        deployment_tx_hash: "22".repeat(32),
        deployment_height: 2,
        bytecode_sha3: HPAY_CHANNEL_EXIT_BYTECODE_SHA3.to_owned(),
        channel_id: "33".repeat(16),
        reuse_version: 7,
        left_address: Address::from(*left.address()).to_readable(),
        right_hub_address: Address::from(*right.address()).to_readable(),
        left_deposit_zhu: 1_000_000,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
    };
    let mut bill = HvmChannelBillV1 {
        schema: HVM_CHANNEL_BILL_SCHEMA.to_owned(),
        binding_commitment: binding.commitment().unwrap(),
        serial: 1,
        left_balance_zhu: binding.left_deposit_zhu,
        right_balance_zhu: 0,
        left_signature_hex: String::new(),
        right_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(&binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
    bill.right_signature_hex = hex::encode(Sign::create_by(&right, &hash).serialize());
    (
        right,
        HvmChannelRecoveryBundleV1 {
            schema: HVM_CHANNEL_RECOVERY_BUNDLE_SCHEMA.to_owned(),
            binding,
            initial_recovery_bill: bill,
        },
    )
}

fn signed_payment_request(
    left: &Account,
    bundle: &HvmChannelRecoveryBundleV1,
    operation_id: &str,
    idempotency_key: &str,
    now: u64,
) -> HvmPaymentRequestV1 {
    let mut bill = HvmChannelBillV1 {
        schema: HVM_CHANNEL_BILL_SCHEMA.to_owned(),
        binding_commitment: bundle.binding.commitment().unwrap(),
        serial: 2,
        left_balance_zhu: bundle.binding.left_deposit_zhu - 100_000,
        right_balance_zhu: 100_000,
        left_signature_hex: String::new(),
        right_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(&bundle.binding).unwrap();
    bill.left_signature_hex = hex::encode(Sign::create_by(left, &hash).serialize());
    HvmPaymentRequestV1 {
        schema: HVM_PAYMENT_REQUEST_SCHEMA.to_owned(),
        operation_id: operation_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        binding_commitment: bundle.binding.commitment().unwrap(),
        payer: bundle.binding.left_address.clone(),
        recipient: "testnet-service-provider".to_owned(),
        amount_zhu: 100_000,
        hub_fee_zhu: 0,
        proposed_bill: bill,
        created_unix: now,
        expires_unix: now + 300,
    }
}

fn capabilities(now: u64) -> Value {
    json!({
        "ret": 0,
        "api_version": 1,
        "api": { "transaction_submit_bound": true },
        "chain": {
            "id": 7,
            "height": 900_000,
            "next_height": 900_001,
            "mainnet": false
        },
        "network": {
            "kind": HPAY_LOCAL_PILOT_NETWORK_KIND,
            "node_profile_id": HPAY_LOCAL_PILOT_PROFILE_ID,
            "block_1_hash": HPAY_LOCAL_PILOT_BLOCK_ONE_HASH,
            "instance_id": HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID,
            "transaction_format_version": 2
        },
        "sync": {
            "tip_timestamp_unix": now,
            "max_tip_age_seconds": 3_600,
            "fresh": true
        },
        // Action 14 is ACTION_HAC_FROM_TO_TRANSFER, now required by the Local
        // Pilot contract proof because a real claim has to move HAC back. The
        // fixture predates that requirement, so the node it describes could not
        // satisfy the proof and the watchtower path refused before it began.
        // Both lists stay ascending: the proof uses action_enabled -> binary_search.
        "actions": {
            "registered": [1, 14, 40, 41, 44, 1041, 1044],
            "enabled": [1, 14, 40, 41, 44, 1041, 1044]
        },
        "transactions": {
            "enabled": [2, 3]
        },
        "features": {
            "channel_unilateral_exit": false,
            "channel_unilateral_exit_evidence": {
                "schema": HPAY_CHANNEL_EXIT_EVIDENCE_SCHEMA,
                "manifest_valid": true,
                "contract_name": HPAY_CHANNEL_EXIT_CONTRACT_NAME,
                "protocol_domain": HPAY_CHANNEL_EXIT_PROTOCOL_DOMAIN,
                "settlement_profile": HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE,
                "source_sha256": "44".repeat(32),
                "bytecode_sha3": HPAY_CHANNEL_EXIT_BYTECODE_SHA3,
                "required_action_kinds": HPAY_CHANNEL_EXIT_ACTION_KINDS,
                "funding_model": {
                    "left_deposit": "positive",
                    "right_hub_deposit": "exactly_zero"
                },
                "storage_key_count": HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT,
                "must_renew_every_storage_key": true,
                "deployment": {
                    "enabled": false,
                    "contract_address": null,
                    "deployment_tx_hash": null,
                    "deployment_height": null,
                    "independently_verified": false
                },
                "on_chain_verification": {
                    "observed_height": null,
                    "confirmed_tx_height": null,
                    "deployment_tx_confirmed": false,
                    "contract_code_sha3": null,
                    "contract_code_matches": false
                },
                "deployment_verified": false
            }
        }
    })
}

fn snapshot(binding: &HvmChannelBindingV1) -> Value {
    json!({
        "ret": 0,
        "schema": HPAY_CHANNEL_LIVE_SNAPSHOT_SCHEMA,
        "chain_id": binding.chain_id,
        "observed_height": 900_000,
        "evaluation_height": 900_001,
        "contract_address": binding.contract_address,
        "deployment_tx_hash": binding.deployment_tx_hash,
        "deployment_height": binding.deployment_height,
        "deployment_action_verified": true,
        "bytecode_sha3": binding.bytecode_sha3,
        "storage_key_count": HPAY_CHANNEL_EXIT_STORAGE_KEY_COUNT,
        "all_keys_active": true,
        "minimum_live_blocks": 10_000,
        "minimum_recover_blocks": 20_000,
        "storage": {
            "status": storage_entry(json!(2)),
            "network": storage_entry(json!(binding.network_instance_id)),
            "channel_id": storage_entry(json!(binding.channel_id)),
            "reuse": storage_entry(json!(binding.reuse_version)),
            "left": storage_entry(json!(binding.left_address)),
            "right": storage_entry(json!(binding.right_hub_address)),
            "left_deposit": storage_entry(json!(binding.left_deposit_zhu)),
            "right_deposit": storage_entry(json!(binding.right_hub_deposit_zhu)),
            "left_paid": storage_entry(json!(binding.left_deposit_zhu)),
            "right_paid": storage_entry(json!(binding.right_hub_deposit_zhu)),
            "total": storage_entry(json!(binding.left_deposit_zhu)),
            "serial": storage_entry(json!(0)),
            "left_balance": storage_entry(json!(binding.left_deposit_zhu)),
            "right_balance": storage_entry(json!(binding.right_hub_deposit_zhu)),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks)),
            "deadline": storage_entry(json!(0)),
            "left_claimed": storage_entry(json!(false)),
            "right_claimed": storage_entry(json!(false))
        }
    })
}

fn bootstrap_snapshot(binding: &HvmChannelBindingV1) -> Value {
    let mut value = snapshot(binding);
    value["minimum_recover_blocks"] = json!(0);
    for entry in value["storage"].as_object_mut().unwrap().values_mut() {
        entry["recover_blocks"] = json!(0);
        entry["active"] = json!(true);
        entry["recoverable"] = json!(false);
    }
    value
}

#[tokio::test]
async fn bootstrap_activation_is_durable_but_cannot_cosign_before_lease_renewal() {
    let left = Account::create_by("hpay-durable-activation-left").unwrap();
    let (hub_account, bundle) = signed_bundle();
    let expected = bundle.binding.clone();
    let live_snapshot = std::sync::Arc::new(tokio::sync::RwLock::new(bootstrap_snapshot(
        &bundle.binding,
    )));
    let served_snapshot = live_snapshot.clone();
    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Json(capabilities(now))
            }),
        )
        .route(
            "/query/hpay/channel-exit",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let expected = expected.clone();
                let served_snapshot = served_snapshot.clone();
                async move {
                    let exact = query.get("contract") == Some(&expected.contract_address)
                        && query.get("deployment_tx_hash") == Some(&expected.deployment_tx_hash)
                        && query.get("deployment_height")
                            == Some(&expected.deployment_height.to_string());
                    if exact {
                        (StatusCode::OK, Json(served_snapshot.read().await.clone()))
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
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");
    let journal_key = "72".repeat(32);
    let state_key = "73".repeat(32);
    let node_url = format!("http://{address}");
    let commitment;
    {
        let hub = HubState::new_secure_with_policy(
            "HVM bootstrap activation test",
            bundle.binding.right_hub_address.clone(),
            node_url.clone(),
            None,
            state_path.clone(),
            secret_hex(&hub_account),
            &journal_key,
            &state_key,
            "testnet",
            1_000_000,
            1_000_000,
        )
        .unwrap();
        commitment = hub
            .activate_hvm_channel_recovery(bundle.clone(), 5_000, 0)
            .await
            .unwrap();
        let request = signed_payment_request(
            &left,
            &bundle,
            "bootstrap-payment-blocked",
            "bootstrap-payment-blocked",
            1_900_000_000,
        );
        assert!(
            hub.cosign_hvm_payment(request, 1_900_000_000)
                .await
                .is_err()
        );
        *live_snapshot.write().await = snapshot(&bundle.binding);
        assert_eq!(
            hub.activate_hvm_channel_recovery(bundle.clone(), 5_000, 0)
                .await
                .unwrap(),
            commitment,
            "an exact activation retry must accept the renewed operational lease state"
        );
        assert!(
            hub.activate_hvm_channel_recovery(bundle.clone(), 5_001, 0)
                .await
                .is_err(),
            "an activation retry cannot silently change its persisted lease policy"
        );
    }
    let reopened = HubState::new_secure_with_policy(
        "HVM bootstrap activation test",
        bundle.binding.right_hub_address.clone(),
        node_url,
        None,
        state_path,
        secret_hex(&hub_account),
        &journal_key,
        &state_key,
        "testnet",
        1_000_000,
        1_000_000,
    )
    .unwrap();
    assert!(
        reopened
            .hvm_recovery_activation_recorded(&commitment)
            .unwrap()
    );
    server.abort();
}

#[tokio::test]
async fn exact_hvm_activation_is_journaled_idempotent_and_survives_restart() {
    let (hub_account, bundle) = signed_bundle();
    let expected = bundle.binding.clone();
    let snapshot = snapshot(&bundle.binding);
    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Json(capabilities(now))
            }),
        )
        .route(
            "/query/hpay/channel-exit",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let expected = expected.clone();
                let snapshot = snapshot.clone();
                async move {
                    let exact = query.get("contract") == Some(&expected.contract_address)
                        && query.get("deployment_tx_hash") == Some(&expected.deployment_tx_hash)
                        && query.get("deployment_height")
                            == Some(&expected.deployment_height.to_string());
                    if exact {
                        (StatusCode::OK, Json(snapshot))
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
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");
    let node_url = format!("http://{address}");
    let journal_key = "52".repeat(32);
    let state_key = "53".repeat(32);
    let commitment;
    {
        let hub = HubState::new_secure_with_policy(
            "HVM activation test",
            bundle.binding.right_hub_address.clone(),
            node_url.clone(),
            None,
            state_path.clone(),
            secret_hex(&hub_account),
            &journal_key,
            &state_key,
            "testnet",
            1_000_000,
            1_000_000,
        )
        .unwrap();
        commitment = hub
            .activate_hvm_channel_recovery(bundle.clone(), 5_000, 5_000)
            .await
            .unwrap();
        assert!(hub.hvm_recovery_activation_recorded(&commitment).unwrap());
        assert_eq!(
            hub.activate_hvm_channel_recovery(bundle.clone(), 5_000, 5_000)
                .await
                .unwrap(),
            commitment
        );
    }
    let reopened = HubState::new_secure_with_policy(
        "HVM activation test",
        bundle.binding.right_hub_address.clone(),
        node_url,
        None,
        state_path,
        secret_hex(&hub_account),
        &journal_key,
        &state_key,
        "testnet",
        1_000_000,
        1_000_000,
    )
    .unwrap();
    assert!(
        reopened
            .hvm_recovery_activation_recorded(&commitment)
            .unwrap()
    );
    assert!(reopened.hvm_recovery_activation_recorded("AA").is_err());
    server.abort();
}

#[tokio::test]
async fn hvm_payment_progression_is_separate_idempotent_and_restart_durable() {
    let left = Account::create_by("hpay-durable-activation-left").unwrap();
    let (hub_account, bundle) = signed_bundle();
    let expected = bundle.binding.clone();
    let live_snapshot = snapshot(&bundle.binding);
    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Json(capabilities(now))
            }),
        )
        .route(
            "/query/hpay/channel-exit",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let expected = expected.clone();
                let live_snapshot = live_snapshot.clone();
                async move {
                    let exact = query.get("contract") == Some(&expected.contract_address)
                        && query.get("deployment_tx_hash") == Some(&expected.deployment_tx_hash)
                        && query.get("deployment_height")
                            == Some(&expected.deployment_height.to_string());
                    if exact {
                        (StatusCode::OK, Json(live_snapshot))
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
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("hub-state.json");
    let node_url = format!("http://{address}");
    let journal_key = "62".repeat(32);
    let state_key = "63".repeat(32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = signed_payment_request(&left, &bundle, "hvm-pay-1", "hvm-idem-1", now);
    let commitment = bundle.binding.commitment().unwrap();
    let signed;
    {
        let hub = HubState::new_secure_with_policy(
            "HVM payment test",
            bundle.binding.right_hub_address.clone(),
            node_url.clone(),
            None,
            state_path.clone(),
            secret_hex(&hub_account),
            &journal_key,
            &state_key,
            "development",
            0,
            0,
        )
        .unwrap();
        hub.activate_hvm_channel_recovery(bundle.clone(), 5_000, 5_000)
            .await
            .unwrap();
        signed = hub
            .cosign_hvm_payment(request.clone(), now)
            .await
            .unwrap()
            .bill;
        signed.validate_fully_signed(&bundle.binding).unwrap();
        assert_eq!(signed.serial, 2);
        assert_eq!(hub.hvm_latest_bill(&commitment).unwrap(), signed);
        let channel_status = hub.hvm_channel_status(&commitment).unwrap();
        assert_eq!(channel_status.schema, HVM_CHANNEL_STATUS_SCHEMA);
        assert_eq!(channel_status.binding_commitment, commitment);
        assert_eq!(channel_status.recovery_bundle, bundle);
        assert_eq!(channel_status.minimum_required_live_blocks, 5_000);
        assert_eq!(channel_status.minimum_required_recover_blocks, 5_000);
        assert_eq!(channel_status.latest_fully_signed_bill, signed);
        assert_eq!(channel_status.updated_unix, now);
        assert!(hub.hvm_channel_status(&"AA".repeat(32)).is_err());
        assert!(hub.hvm_channel_status(&"0".repeat(64)).is_err());
        assert_eq!(
            hub.hvm_payment_request(&request.operation_id).unwrap(),
            Some(request.clone())
        );
        let status = hub.hvm_payment_status(&request.operation_id).unwrap();
        assert_eq!(status.status, "fully_signed");
        assert_eq!(status.request, request);
        assert_eq!(status.fully_signed_bill.as_ref(), Some(&signed));
        assert!(!status.recovery_required);
        assert_eq!(
            hub.cosign_hvm_payment(status.request.clone(), now + 1)
                .await
                .unwrap()
                .bill,
            signed
        );

        let mut reused_key =
            signed_payment_request(&left, &bundle, "hvm-pay-2", "hvm-idem-1", now + 1);
        reused_key.proposed_bill.serial = 3;
        assert!(hub.cosign_hvm_payment(reused_key, now + 1).await.is_err());
    }
    let reopened = HubState::new_secure_with_policy(
        "HVM payment test",
        bundle.binding.right_hub_address.clone(),
        node_url,
        None,
        state_path,
        secret_hex(&hub_account),
        &journal_key,
        &state_key,
        "development",
        0,
        0,
    )
    .unwrap();
    assert_eq!(reopened.hvm_latest_bill(&commitment).unwrap(), signed);
    assert_eq!(
        reopened
            .hvm_channel_status(&commitment)
            .unwrap()
            .latest_fully_signed_bill,
        signed
    );
    assert_eq!(
        reopened
            .cosign_hvm_payment(request, now + 2)
            .await
            .unwrap()
            .bill,
        signed
    );
    server.abort();
}

#[test]
fn watchtower_handles_stale_challenge_deadline_unknown_serial_and_reorg_snapshot() {
    let left = Account::create_by("hpay-durable-activation-left").unwrap();
    let (_hub, bundle) = signed_bundle();
    let now = 1_900_000_000;
    let request = signed_payment_request(&left, &bundle, "watch-bill", "watch-idem", now);
    let right = Account::create_by("hpay-durable-activation-right").unwrap();
    let mut latest = request.proposed_bill;
    let hash = latest.signing_hash(&bundle.binding).unwrap();
    latest.right_signature_hex = hex::encode(Sign::create_by(&right, &hash).serialize());

    let open: l2_fast_pay_hub::node::HvmChannelLiveSnapshot =
        serde_json::from_value(snapshot(&bundle.binding)).unwrap();
    assert_eq!(
        decide_watchtower_action(&open, &bundle.binding, &latest).unwrap(),
        HvmWatchtowerDecision::NoAction
    );

    let mut stale_challenge = open.clone();
    stale_challenge.storage.status.value = 3;
    stale_challenge.storage.serial.value = 1;
    stale_challenge.storage.left_balance.value = 900_000;
    stale_challenge.storage.right_balance.value = 100_000;
    stale_challenge.storage.deadline.value = stale_challenge.observed_height + 12;
    assert_eq!(
        decide_watchtower_action(&stale_challenge, &bundle.binding, &latest).unwrap(),
        HvmWatchtowerDecision::RespondWithLatestBill
    );

    let mut expired = stale_challenge.clone();
    expired.storage.deadline.value = expired.observed_height;
    assert_eq!(
        decide_watchtower_action(&expired, &bundle.binding, &latest).unwrap(),
        HvmWatchtowerDecision::Finalize
    );

    let mut unknown = stale_challenge;
    unknown.storage.serial.value = latest.serial + 1;
    assert_eq!(
        decide_watchtower_action(&unknown, &bundle.binding, &latest).unwrap(),
        HvmWatchtowerDecision::RecoveryRequired
    );

    // A reorg-like return to the authenticated open snapshot is harmless and
    // never reuses the stale challenge decision.
    assert_eq!(
        decide_watchtower_action(&open, &bundle.binding, &latest).unwrap(),
        HvmWatchtowerDecision::NoAction
    );

    // FINAL, and the settled principal is still inside the contract. This
    // answered `NoAction` for the whole life of the V1 rail, which is how
    // 0.99 HAC came to sit in a finalized chain-7 channel that nothing
    // shipped could reach.
    let mut settled = open.clone();
    settled.storage.status.value = 4;
    settled.storage.serial.value = latest.serial;
    settled.storage.left_balance.value = latest.left_balance_zhu;
    settled.storage.right_balance.value = latest.right_balance_zhu;
    settled.storage.deadline.value = settled.observed_height;
    assert_eq!(
        decide_watchtower_action(&settled, &bundle.binding, &latest).unwrap(),
        HvmWatchtowerDecision::ClaimLeftPayout
    );

    // Paid already, by us or by any third party: the payout is permissionless
    // and `left_claimed` is the contract's own evidence that it happened.
    let mut claimed = settled.clone();
    claimed.storage.left_claimed.value = true;
    assert_eq!(
        decide_watchtower_action(&claimed, &bundle.binding, &latest).unwrap(),
        HvmWatchtowerDecision::NoAction
    );

    // A FINAL split the Hub's own ledger does not hold is a person's problem,
    // not a payout: claiming there would give away the Hub's earned balance
    // on a state it cannot explain.
    let mut disagreeing = settled;
    disagreeing.storage.left_balance.value = latest.left_balance_zhu + 1;
    disagreeing.storage.right_balance.value = latest.right_balance_zhu - 1;
    assert_eq!(
        decide_watchtower_action(&disagreeing, &bundle.binding, &latest).unwrap(),
        HvmWatchtowerDecision::RecoveryRequired
    );

    // `RecoveryRequired` comes back from three unrelated situations and the
    // caller reports all three with one sentence. That sentence used to be
    // "chain serial is newer than the authenticated HVM ledger" in every case,
    // which is the opposite of the truth for the two below, where the serial is
    // equal. An operator sent after the wrong problem is worse off than one
    // told nothing, so each cause has to name itself.
    let newer = recovery_required_reason(&unknown, &latest);
    assert!(
        newer.contains("is newer than the authenticated HVM ledger"),
        "a genuinely newer chain serial must still say so: {newer}"
    );

    let split = recovery_required_reason(&disagreeing, &latest);
    assert!(
        split.contains("FINAL on a split"),
        "a disagreeing FINAL split must name itself: {split}"
    );
    assert!(
        !split.contains("is newer than"),
        "the serial here is equal, so the reason must not claim it is newer: {split}"
    );
    assert!(
        split.contains(&latest.left_balance_zhu.to_string())
            && split.contains(&disagreeing.storage.left_balance.value.to_string()),
        "the reason must carry both sides of the disagreement: {split}"
    );

    // The third `RecoveryRequired` branch, `_ =>` on an unhandled chain status,
    // cannot be reached through `decide_watchtower_action`: it calls
    // `validate_runtime_binding` first, and that refuses any status outside
    // `2..=4` with "live HPAY HVM runtime state is inconsistent with its
    // binding". The arm is defensive, and so is the reason for it. Asserted
    // against the reason function directly, because the only way to reach it is
    // for that validator to change.
    let mut unhandled = disagreeing;
    unhandled.storage.status.value = 9;
    unhandled.storage.serial.value = latest.serial;
    assert!(
        decide_watchtower_action(&unhandled, &bundle.binding, &latest).is_err(),
        "an out-of-range chain status must be refused before any decision is reached"
    );
    let unhandled_reason = recovery_required_reason(&unhandled, &latest);
    assert!(
        unhandled_reason.contains("status 9") && !unhandled_reason.contains("is newer than"),
        "an unhandled chain status must name the status, not the serial: {unhandled_reason}"
    );
}

#[cfg(feature = "local-pilot-tools")]
#[tokio::test]
async fn watchtower_respond_is_broadcast_confirmed_and_restart_idempotent() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let left = Account::create_by("hpay-durable-activation-left").unwrap();
    let (hub_account, bundle) = signed_bundle();
    let expected = bundle.binding.clone();
    let live = Arc::new(tokio::sync::RwLock::new(snapshot(&bundle.binding)));
    let submitted = Arc::new(tokio::sync::RwLock::new(Vec::<String>::new()));
    let accepted = Arc::new(tokio::sync::RwLock::new(String::new()));
    let submit_count = Arc::new(AtomicUsize::new(0));
    let fail_next_submit = Arc::new(AtomicBool::new(false));
    let query_mode = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Json(capabilities(now))
            }),
        )
        .route(
            "/query/hpay/channel-exit",
            get({
                let live = live.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let expected = expected.clone();
                    let live = live.clone();
                    async move {
                        assert_eq!(query.get("contract"), Some(&expected.contract_address));
                        (StatusCode::OK, Json(live.read().await.clone()))
                    }
                }
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let submitted = submitted.clone();
                let submit_count = submit_count.clone();
                let fail_next_submit = fail_next_submit.clone();
                let accepted = accepted.clone();
                let live = live.clone();
                move |body: String| {
                    let submitted = submitted.clone();
                    let submit_count = submit_count.clone();
                    let fail_next_submit = fail_next_submit.clone();
                    let accepted = accepted.clone();
                    let live = live.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (transaction, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        let transaction_hash = hex::encode(transaction.hash().as_bytes());
                        let attempt = submit_count.fetch_add(1, Ordering::SeqCst) + 1;
                        submitted.write().await.push(body);
                        if fail_next_submit.swap(false, Ordering::SeqCst) {
                            Json(json!({"ret": 1, "err": "simulated uncertain submit"}))
                        } else {
                            *accepted.write().await =
                                submitted.read().await.last().cloned().unwrap();
                            let mut snapshot = live.write().await;
                            if attempt == 3 {
                                snapshot["minimum_live_blocks"] = json!(10_100);
                                snapshot["minimum_recover_blocks"] = json!(20_100);
                                if let Some(storage) = snapshot["storage"].as_object_mut() {
                                    for entry in storage.values_mut() {
                                        entry["live_blocks"] = json!(10_100);
                                        entry["recover_blocks"] = json!(20_100);
                                    }
                                }
                            } else if attempt == 1 {
                                snapshot["storage"]["status"]["value"] = json!(3);
                                snapshot["storage"]["serial"]["value"] = json!(1);
                                snapshot["storage"]["left_balance"]["value"] = json!(1_000_000);
                                snapshot["storage"]["right_balance"]["value"] = json!(0);
                                snapshot["storage"]["deadline"]["value"] = json!(900_012);
                            } else {
                                snapshot["storage"]["status"]["value"] = json!(3);
                                snapshot["storage"]["serial"]["value"] = json!(2);
                                snapshot["storage"]["left_balance"]["value"] = json!(900_000);
                                snapshot["storage"]["right_balance"]["value"] = json!(100_000);
                            }
                            Json(json!({"ret": 0, "hash": transaction_hash}))
                        }
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get({
                let accepted = accepted.clone();
                let query_mode = query_mode.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let accepted = accepted.clone();
                    let query_mode = query_mode.clone();
                    async move {
                        let body = accepted.read().await.clone();
                        let mode = query_mode.load(Ordering::SeqCst);
                        if body.is_empty() || mode == 2 {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        }
                        Json(json!({
                            "ret": 0,
                            "hash": query.get("hash").cloned().unwrap(),
                            "tx_type": 3,
                            "body": body,
                            "actions": [{"kind": 44}],
                            "signatures": [{"complete": true}],
                            "block": {"height": 900_010},
                            "confirm": if mode == 1 { 2 } else { 6 }
                        }))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("watchtower-state.json");
    let node_url = format!("http://{address}");
    let journal_key = "72".repeat(32);
    let state_key = "73".repeat(32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payment = signed_payment_request(&left, &bundle, "watch-pay", "watch-pay-idem", now);
    let watch_request = HvmWatchtowerRequestV1 {
        schema: HVM_WATCHTOWER_REQUEST_SCHEMA.into(),
        operation_id: "watchtower-respond-1".into(),
        idempotency_key: "watchtower-respond-idem-1".into(),
        binding_commitment: bundle.binding.commitment().unwrap(),
        mode: HvmWatchtowerMode::Monitor,
        network_fee_zhu: 10_000,
        timestamp: now,
        gas_max: u8::MAX,
        created_unix: now,
    };
    let stale_request = HvmWatchtowerRequestV1 {
        schema: HVM_WATCHTOWER_REQUEST_SCHEMA.into(),
        operation_id: "watchtower-local-pilot-stale-1".into(),
        idempotency_key: "watchtower-local-pilot-stale-idem-1".into(),
        binding_commitment: bundle.binding.commitment().unwrap(),
        mode: HvmWatchtowerMode::BeginChallenge,
        network_fee_zhu: 10_000,
        timestamp: now - 1,
        gas_max: u8::MAX,
        created_unix: now - 1,
    };
    let renewal_request = HvmLeaseRenewalRequestV1 {
        schema: HVM_LEASE_RENEWAL_REQUEST_SCHEMA.into(),
        operation_id: "lease-renew-all-1".into(),
        idempotency_key: "lease-renew-all-idem-1".into(),
        binding_commitment: bundle.binding.commitment().unwrap(),
        renew_when_live_blocks_at_or_below: 10_000,
        periods: 100,
        network_fee_zhu: 10_000,
        timestamp: now + 1,
        gas_max: u8::MAX,
        created_unix: now + 1,
    };
    {
        let hub = HubState::new_secure_with_policy(
            "watchtower test",
            bundle.binding.right_hub_address.clone(),
            node_url.clone(),
            None,
            state_path.clone(),
            secret_hex(&hub_account),
            &journal_key,
            &state_key,
            "local-pilot",
            0,
            0,
        )
        .unwrap();
        hub.activate_hvm_channel_recovery(bundle.clone(), 5_000, 5_000)
            .await
            .unwrap();
        hub.cosign_hvm_payment(payment, now).await.unwrap();
        let stale = hub
            .run_hvm_local_pilot_stale_challenge(stale_request.clone())
            .await
            .unwrap();
        assert_eq!(stale.status, "confirmed");
        assert_eq!(stale.action, "challenge");
        assert_eq!(
            hub.hvm_watchtower_request(&stale_request.operation_id)
                .unwrap(),
            Some(stale_request)
        );
        assert_eq!(submit_count.load(Ordering::SeqCst), 1);
        let response = hub.run_hvm_watchtower(watch_request.clone()).await.unwrap();
        assert_eq!(response.status, "confirmed");
        assert_eq!(response.observed_confirmations, 6);
        assert_eq!(
            hub.hvm_watchtower_request(&watch_request.operation_id)
                .unwrap(),
            Some(watch_request.clone())
        );
        assert_eq!(submit_count.load(Ordering::SeqCst), 2);
        let renewal = hub
            .run_hvm_lease_renewal(renewal_request.clone())
            .await
            .unwrap();
        assert_eq!(renewal.status, "confirmed");
        assert_eq!(renewal.action, "renew_all_leases");
        assert_eq!(
            hub.hvm_lease_renewal_request(
                &renewal_request.operation_id,
                renewal_request.renew_when_live_blocks_at_or_below,
            )
            .unwrap(),
            Some(renewal_request.clone())
        );
        assert!(
            hub.hvm_lease_renewal_request(
                &renewal_request.operation_id,
                renewal_request.renew_when_live_blocks_at_or_below - 1,
            )
            .is_err(),
            "a changed lease admission threshold must fail its durable commitment"
        );
        assert_eq!(submit_count.load(Ordering::SeqCst), 3);

        let mut uncertain = watch_request.clone();
        uncertain.operation_id = "watchtower-respond-uncertain".into();
        uncertain.idempotency_key = "watchtower-respond-uncertain-idem".into();
        uncertain.timestamp += 2;
        uncertain.created_unix += 2;
        {
            let mut snapshot = live.write().await;
            snapshot["storage"]["serial"]["value"] = json!(1);
            snapshot["storage"]["left_balance"]["value"] = json!(900_000);
            snapshot["storage"]["right_balance"]["value"] = json!(100_000);
        }
        *accepted.write().await = String::new();
        fail_next_submit.store(true, Ordering::SeqCst);
        let recovery = hub.run_hvm_watchtower(uncertain.clone()).await.unwrap();
        assert_eq!(recovery.status, "recovery_required");
        assert_eq!(submit_count.load(Ordering::SeqCst), 4);
        let reconciled = hub
            .reconcile_hvm_watchtower(&uncertain.operation_id, true)
            .await
            .unwrap();
        assert_eq!(reconciled.status, "confirmed");
        assert_eq!(submit_count.load(Ordering::SeqCst), 5);
        let bodies = submitted.read().await;
        assert_eq!(
            bodies[3], bodies[4],
            "recovery must reuse exact signed bytes"
        );
        drop(bodies);

        let mut reorg = watch_request.clone();
        reorg.operation_id = "watchtower-pre-finality-reorg".into();
        reorg.idempotency_key = "watchtower-pre-finality-reorg-idem".into();
        reorg.timestamp += 3;
        reorg.created_unix += 3;
        {
            let mut snapshot = live.write().await;
            snapshot["storage"]["serial"]["value"] = json!(1);
            snapshot["storage"]["left_balance"]["value"] = json!(900_000);
            snapshot["storage"]["right_balance"]["value"] = json!(100_000);
        }
        query_mode.store(1, Ordering::SeqCst);
        let shallow = hub.run_hvm_watchtower(reorg.clone()).await.unwrap();
        assert_eq!(shallow.status, "submitted");
        assert_eq!(shallow.observed_confirmations, 2);
        assert_eq!(submit_count.load(Ordering::SeqCst), 6);
        query_mode.store(2, Ordering::SeqCst);
        let frozen = hub.run_hvm_watchtower(reorg).await.unwrap();
        assert_eq!(frozen.status, "recovery_required");
        assert_eq!(submit_count.load(Ordering::SeqCst), 6);
        query_mode.store(0, Ordering::SeqCst);
        assert_eq!(
            hub.run_hvm_lease_renewal(renewal_request.clone())
                .await
                .unwrap()
                .status,
            "confirmed"
        );
        assert_eq!(submit_count.load(Ordering::SeqCst), 6);
    }
    let reopened = HubState::new_secure_with_policy(
        "watchtower test",
        bundle.binding.right_hub_address.clone(),
        node_url,
        None,
        state_path,
        secret_hex(&hub_account),
        &journal_key,
        &state_key,
        "local-pilot",
        0,
        0,
    )
    .unwrap();
    let response = reopened.run_hvm_watchtower(watch_request).await.unwrap();
    assert_eq!(response.status, "confirmed");
    assert_eq!(
        reopened
            .run_hvm_lease_renewal(renewal_request)
            .await
            .unwrap()
            .status,
        "confirmed"
    );
    assert_eq!(submit_count.load(Ordering::SeqCst), 6);
    server.abort();
}

#[cfg(feature = "local-pilot-tools")]
#[tokio::test]
async fn concurrent_watchtower_and_renewal_admit_only_one_uncertain_operation() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let (hub_account, bundle) = signed_bundle();
    let expected = bundle.binding.clone();
    let live = Arc::new(tokio::sync::RwLock::new(snapshot(&bundle.binding)));
    let submit_count = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/query/capabilities",
            get(|| async {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                Json(capabilities(now))
            }),
        )
        .route(
            "/query/hpay/channel-exit",
            get({
                let live = live.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let expected = expected.clone();
                    let live = live.clone();
                    async move {
                        assert_eq!(query.get("contract"), Some(&expected.contract_address));
                        (StatusCode::OK, Json(live.read().await.clone()))
                    }
                }
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let submit_count = submit_count.clone();
                move |_body: String| {
                    let submit_count = submit_count.clone();
                    async move {
                        submit_count.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        Json(json!({"ret": 1, "err": "simulated uncertain submit"}))
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get(|| async { Json(json!({"ret": 1, "err": "transaction not found"})) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let directory = tempdir().unwrap();
    let state_path = directory.path().join("race-state.json");
    let journal_key = "82".repeat(32);
    let state_key = "83".repeat(32);
    let node_url = format!("http://{address}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let watch_request = HvmWatchtowerRequestV1 {
        schema: HVM_WATCHTOWER_REQUEST_SCHEMA.into(),
        operation_id: "race-watchtower".into(),
        idempotency_key: "race-watchtower-idem".into(),
        binding_commitment: bundle.binding.commitment().unwrap(),
        mode: HvmWatchtowerMode::BeginChallenge,
        network_fee_zhu: 10_000,
        timestamp: now,
        gas_max: u8::MAX,
        created_unix: now,
    };
    let renewal_request = HvmLeaseRenewalRequestV1 {
        schema: HVM_LEASE_RENEWAL_REQUEST_SCHEMA.into(),
        operation_id: "race-renewal".into(),
        idempotency_key: "race-renewal-idem".into(),
        binding_commitment: bundle.binding.commitment().unwrap(),
        renew_when_live_blocks_at_or_below: 10_000,
        periods: 100,
        network_fee_zhu: 10_000,
        timestamp: now + 1,
        gas_max: u8::MAX,
        created_unix: now + 1,
    };
    let (watch_won, winning_operation_id, winning_idempotency_key) = {
        let hub = HubState::new_secure_with_policy(
            "HVM operation race test",
            bundle.binding.right_hub_address.clone(),
            node_url.clone(),
            None,
            state_path.clone(),
            secret_hex(&hub_account),
            &journal_key,
            &state_key,
            "local-pilot",
            0,
            0,
        )
        .unwrap();
        hub.activate_hvm_channel_recovery(bundle.clone(), 5_000, 5_000)
            .await
            .unwrap();

        let (watch_result, renewal_result) = tokio::join!(
            hub.run_hvm_local_pilot_stale_challenge(watch_request.clone()),
            hub.run_hvm_lease_renewal(renewal_request.clone())
        );
        assert_eq!(submit_count.load(Ordering::SeqCst), 1);
        assert_ne!(watch_result.is_ok(), renewal_result.is_ok());
        let winning_response = watch_result
            .as_ref()
            .ok()
            .or(renewal_result.as_ref().ok())
            .unwrap();
        assert_eq!(winning_response.status, "recovery_required");
        let watch_won = watch_result.is_ok();

        if watch_won {
            let mut changed_same_operation = watch_request.clone();
            changed_same_operation.idempotency_key = "changed-watchtower-idem".into();
            assert!(
                hub.run_hvm_local_pilot_stale_challenge(changed_same_operation)
                    .await
                    .is_err()
            );
            let mut reused_idempotency = watch_request.clone();
            reused_idempotency.operation_id = "different-watchtower-operation".into();
            assert!(
                hub.run_hvm_local_pilot_stale_challenge(reused_idempotency)
                    .await
                    .is_err()
            );
        } else {
            let mut changed_same_operation = renewal_request.clone();
            changed_same_operation.periods += 1;
            assert!(
                hub.run_hvm_lease_renewal(changed_same_operation)
                    .await
                    .is_err()
            );
            let mut reused_idempotency = renewal_request.clone();
            reused_idempotency.operation_id = "different-renewal-operation".into();
            assert!(hub.run_hvm_lease_renewal(reused_idempotency).await.is_err());
        }
        assert_eq!(submit_count.load(Ordering::SeqCst), 1);
        (
            watch_won,
            winning_response.operation_id.clone(),
            if watch_won {
                watch_request.idempotency_key.clone()
            } else {
                renewal_request.idempotency_key.clone()
            },
        )
    };

    let reopened = HubState::new_secure_with_policy(
        "HVM operation race test",
        bundle.binding.right_hub_address.clone(),
        node_url,
        None,
        state_path,
        secret_hex(&hub_account),
        &journal_key,
        &state_key,
        "local-pilot",
        0,
        0,
    )
    .unwrap();
    if watch_won {
        assert_eq!(
            reopened
                .hvm_watchtower_request(&winning_operation_id)
                .unwrap()
                .unwrap()
                .idempotency_key,
            winning_idempotency_key
        );
        assert!(
            reopened
                .run_hvm_lease_renewal(renewal_request)
                .await
                .is_err()
        );
    } else {
        assert_eq!(
            reopened
                .hvm_lease_renewal_request(
                    &winning_operation_id,
                    renewal_request.renew_when_live_blocks_at_or_below,
                )
                .unwrap()
                .unwrap()
                .idempotency_key,
            winning_idempotency_key
        );
        assert!(
            reopened
                .run_hvm_local_pilot_stale_challenge(watch_request)
                .await
                .is_err()
        );
    }
    assert_eq!(submit_count.load(Ordering::SeqCst), 1);
    server.abort();
}
