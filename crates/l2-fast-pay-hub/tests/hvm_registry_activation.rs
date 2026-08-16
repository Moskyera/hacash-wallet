use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::routing::{get, post};
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
use l2_fast_pay_hub::hvm_registry_watchtower::{
    HVM_REGISTRY_LEASE_REQUEST_SCHEMA, HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA,
    HvmRegistryLeaseRenewalRequestV2, HvmRegistryWatchtowerModeV2, HvmRegistryWatchtowerRequestV2,
};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use serde_json::{Value, json};
use sys::Account;
use tempfile::tempdir;
use tokio::sync::RwLock;
use vm::ContractAddress;

const NETWORK_KIND: &str = "local_pilot_v1";
const PROFILE_ID: &str = "hpay-local-pilot-chain-v1";
const BLOCK_ONE: &str = "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29";
const INSTANCE: &str = "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3";

fn secret_hex(account: &Account) -> String {
    hex::encode(account.secret_key().serialize())
}

fn capabilities(now: u64) -> Value {
    json!({
        "ret": 0,
        "api_version": 1,
        "api": {
            "transaction_submit_bound": true,
            "hpay_channel_registry_query": true
        },
        "chain": {
            "id": 7,
            "height": 900_000,
            "next_height": 900_001,
            "mainnet": false
        },
        "network": {
            "kind": NETWORK_KIND,
            "node_profile_id": PROFILE_ID,
            "block_1_hash": BLOCK_ONE,
            "instance_id": INSTANCE,
            "transaction_format_version": 2
        },
        "sync": {
            "tip_timestamp_unix": now,
            "max_tip_age_seconds": 3_600,
            "fresh": true
        },
        // Action 2 is ACTION_CHANNEL_OPEN. The node capability gate requires it
        // alongside transaction 2 and action 0x0411 before it will accept the
        // channel-open topology, and this fixture omitted it, so the whole
        // registry activation path refused at the first binding read. Both lists
        // stay ascending: the gate uses binary_search.
        "actions": {
            "registered": [1, 2, 14, 40, 41, 44, 1041, 1044],
            "enabled": [1, 2, 14, 40, 41, 44, 1041, 1044]
        },
        "transactions": { "enabled": [2, 3] },
        "features": { "channel_unilateral_exit": false }
    })
}

fn network_binding() -> L1ChannelNetworkBinding {
    let binding = L1ChannelNetworkBinding::from_node_identity(
        NETWORK_KIND,
        false,
        7,
        BLOCK_ONE,
        PROFILE_ID,
        Some(INSTANCE),
        2,
    )
    .unwrap();
    assert_eq!(binding.network_instance_id, INSTANCE);
    binding
}

fn storage_entry(value: Value, live: u64, recover: u64) -> Value {
    json!({
        "value": value,
        "live_blocks": live,
        "recover_blocks": recover,
        "active": true,
        "recoverable": false
    })
}

fn snapshot(binding: &HvmRegistryBindingV2, live: u64, recover: u64) -> Value {
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
        "minimum_live_blocks": live,
        "minimum_recover_blocks": recover,
        "registry": {
            "g_network": storage_entry(json!(binding.network_instance_id), live, recover),
            "g_hub": storage_entry(json!(binding.right_hub_address), live, recover),
            "g_locked": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "g_left_claimable": storage_entry(json!(0), live, recover),
            "g_hub_claimable": storage_entry(json!(0), live, recover),
            "g_open_count": storage_entry(json!(1), live, recover)
        },
        "channel": {
            "status": storage_entry(json!(2), live, recover),
            "channel_id": storage_entry(json!(binding.channel_id), live, recover),
            "reuse": storage_entry(json!(binding.reuse_version), live, recover),
            "deposit": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "paid": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "total": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "serial": storage_entry(json!(0), live, recover),
            "left_balance": storage_entry(json!(binding.left_deposit_zhu), live, recover),
            "hub_balance": storage_entry(json!(0), live, recover),
            "challenge_blocks": storage_entry(json!(binding.challenge_blocks), live, recover),
            "deadline": storage_entry(json!(0), live, recover),
            "left_claimed": storage_entry(json!(false), live, recover)
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
    now: u64,
) -> HvmRegistryPaymentRequestV2 {
    let mut request = HvmRegistryPaymentRequestV2::build_unsigned(
        &network_binding(),
        &bundle.binding,
        &bundle.initial_recovery_bill,
        "registry-payment-1",
        "registry-payment-idempotency-1",
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

#[tokio::test]
async fn bootstrap_renewal_payment_and_restart_are_exact_and_fee_free() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub_account = Account::create_by("registry-integration-hub").unwrap();
    let contract =
        ContractAddress::from_unchecked(Address::create_contract([0x31; 20])).to_readable();
    let (left, bundle) = signed_bundle("registry-integration-left", &hub_account, &contract);
    let expected_binding = bundle.binding.clone();
    let live = Arc::new(RwLock::new(snapshot(&bundle.binding, 10_000, 0)));
    let accepted_body = Arc::new(RwLock::new(String::new()));
    let accepted_hash = Arc::new(RwLock::new(String::new()));
    let submit_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

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
            "/query/hpay/channel-registry",
            get({
                let live = live.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let live = live.clone();
                    let expected = expected_binding.clone();
                    async move {
                        let exact = query.get("contract") == Some(&expected.contract_address)
                            && query.get("deployment_tx_hash")
                                == Some(&expected.deployment_tx_hash)
                            && query.get("deployment_height")
                                == Some(&expected.deployment_height.to_string())
                            && query.get("left") == Some(&expected.left_address);
                        if exact {
                            (StatusCode::OK, Json(live.read().await.clone()))
                        } else {
                            (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"ret": 1, "err": "binding mismatch"})),
                            )
                        }
                    }
                }
            }),
        )
        .route(
            "/submit/transaction/hpay-bound",
            post({
                let live = live.clone();
                let accepted_body = accepted_body.clone();
                let accepted_hash = accepted_hash.clone();
                let submit_count = submit_count.clone();
                move |body: String| {
                    let live = live.clone();
                    let accepted_body = accepted_body.clone();
                    let accepted_hash = accepted_hash.clone();
                    let submit_count = submit_count.clone();
                    async move {
                        let raw = hex::decode(&body).unwrap();
                        let (transaction, consumed) =
                            protocol::transaction::transaction_create(&raw).unwrap();
                        assert_eq!(consumed, raw.len());
                        assert_eq!(transaction.ty(), 3);
                        transaction.verify_signature().unwrap();
                        let hash = hex::encode(transaction.hash().as_bytes());
                        let attempt =
                            submit_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        *accepted_body.write().await = body;
                        *accepted_hash.write().await = hash.clone();
                        let mut current = live.write().await;
                        match attempt {
                            1 => {
                                current["minimum_live_blocks"] = json!(20_000);
                                current["minimum_recover_blocks"] = json!(30_000);
                                for group in ["registry", "channel"] {
                                    for entry in
                                        current[group].as_object_mut().unwrap().values_mut()
                                    {
                                        entry["live_blocks"] = json!(20_000);
                                        entry["recover_blocks"] = json!(30_000);
                                        entry["active"] = json!(true);
                                        entry["recoverable"] = json!(false);
                                    }
                                }
                            }
                            2 => {
                                current["channel"]["status"]["value"] = json!(3);
                                #[cfg(feature = "local-pilot-tools")]
                                {
                                    current["channel"]["serial"]["value"] = json!(1);
                                    current["channel"]["left_balance"]["value"] = json!(1_000_000);
                                    current["channel"]["hub_balance"]["value"] = json!(0);
                                }
                                #[cfg(not(feature = "local-pilot-tools"))]
                                {
                                    current["channel"]["serial"]["value"] = json!(2);
                                    current["channel"]["left_balance"]["value"] = json!(900_000);
                                    current["channel"]["hub_balance"]["value"] = json!(100_000);
                                }
                                current["channel"]["deadline"]["value"] = json!(900_012);
                            }
                            3 => {
                                current["channel"]["status"]["value"] = json!(3);
                                current["channel"]["serial"]["value"] = json!(2);
                                current["channel"]["left_balance"]["value"] = json!(900_000);
                                current["channel"]["hub_balance"]["value"] = json!(100_000);
                            }
                            4 => {
                                current["channel"]["status"]["value"] = json!(4);
                            }
                            other => panic!("unexpected registry submit attempt {other}"),
                        }
                        Json(json!({"ret": 0, "hash": hash}))
                    }
                }
            }),
        )
        .route(
            "/query/transaction",
            get({
                let accepted_body = accepted_body.clone();
                let accepted_hash = accepted_hash.clone();
                move |Query(query): Query<HashMap<String, String>>| {
                    let accepted_body = accepted_body.clone();
                    let accepted_hash = accepted_hash.clone();
                    async move {
                        let body = accepted_body.read().await.clone();
                        let hash = accepted_hash.read().await.clone();
                        if body.is_empty() || query.get("hash") != Some(&hash) {
                            return Json(json!({"ret": 1, "err": "transaction not found"}));
                        }
                        Json(json!({
                            "ret": 0,
                            "hash": hash,
                            "tx_type": 3,
                            "body": body,
                            "actions": [{"kind": 1041}, {"kind": 44}],
                            "signatures": [{"complete": true}],
                            // A confirmation is only reorg-detectable if it
                            // names the block it lives in, so the fullnode's
                            // canonical block hash is part of the evidence.
                            "block": {"height": 900_010, "hash": "5c".repeat(32)},
                            "confirm": 6
                        }))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempdir().unwrap();
    let state_path = directory.path().join("registry-state.json");
    let node_url = format!("http://{address}");
    let journal_key = "92".repeat(32);
    let state_key = "93".repeat(32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let binding_commitment = bundle.binding.commitment().unwrap();
    let renewal = HvmRegistryLeaseRenewalRequestV2 {
        schema: HVM_REGISTRY_LEASE_REQUEST_SCHEMA.into(),
        operation_id: "registry-renewal-1".into(),
        idempotency_key: "registry-renewal-idempotency-1".into(),
        binding_commitment: binding_commitment.clone(),
        renew_when_blocks_at_or_below: 1,
        periods: 100,
        network_fee_zhu: 10_000,
        timestamp: now,
        gas_max: u8::MAX,
        created_unix: now,
    };
    let mut concurrent_renewal = renewal.clone();
    concurrent_renewal.operation_id = "registry-renewal-2".into();
    concurrent_renewal.idempotency_key = "registry-renewal-idempotency-2".into();
    concurrent_renewal.timestamp = now + 1;
    concurrent_renewal.created_unix = now + 1;
    let payment = left_signed_payment(&left, &bundle, now + 1);
    let signed;
    let confirmed_renewal_operation;
    {
        let hub = HubState::new_secure_with_policy(
            "registry integration",
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
        hub.activate_hvm_registry_recovery(bundle.clone(), 5_000, 0)
            .await
            .unwrap();
        assert!(
            hub.cosign_hvm_registry_payment(payment.clone(), now + 1)
                .await
                .is_err(),
            "bootstrap leases must block payment key use"
        );
        let (first, second) = tokio::join!(
            hub.run_hvm_registry_lease_renewal(renewal.clone()),
            hub.run_hvm_registry_lease_renewal(concurrent_renewal.clone())
        );
        let first = first.unwrap();
        let second = second.unwrap();
        let statuses = [first.status.as_str(), second.status.as_str()];
        assert!(statuses.contains(&"confirmed"));
        assert!(statuses.contains(&"no_action"));
        let confirmed = if first.status == "confirmed" {
            &first
        } else {
            &second
        };
        assert_eq!(confirmed.action, "renew_all_leases");
        assert_eq!(confirmed.observed_confirmations, 6);
        confirmed_renewal_operation = confirmed.operation_id.clone();
        assert_eq!(submit_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        signed = hub
            .cosign_hvm_registry_payment(payment.clone(), now + 1)
            .await
            .unwrap();
        signed.validate_fully_signed(&bundle.binding).unwrap();
        assert_eq!(payment.hub_fee_zhu, 0);
        assert_eq!(signed.hub_balance_zhu, payment.amount_zhu);
        assert_eq!(
            hub.cosign_hvm_registry_payment(payment.clone(), now + 2)
                .await
                .unwrap(),
            signed
        );

        let challenge = HvmRegistryWatchtowerRequestV2 {
            schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
            operation_id: "registry-challenge-1".into(),
            idempotency_key: "registry-challenge-idempotency-1".into(),
            binding_commitment: binding_commitment.clone(),
            mode: HvmRegistryWatchtowerModeV2::BeginChallenge,
            network_fee_zhu: 10_000,
            timestamp: now + 2,
            gas_max: u8::MAX,
            created_unix: now + 2,
        };
        #[cfg(feature = "local-pilot-tools")]
        let challenged = hub
            .run_hvm_registry_local_pilot_stale_challenge(challenge)
            .await
            .unwrap();
        #[cfg(not(feature = "local-pilot-tools"))]
        let challenged = hub.run_hvm_registry_watchtower(challenge).await.unwrap();
        assert_eq!(challenged.status, "confirmed");
        assert_eq!(challenged.action, "challenge");

        #[cfg(not(feature = "local-pilot-tools"))]
        {
            let mut stale = live.write().await;
            stale["channel"]["serial"]["value"] = json!(1);
            stale["channel"]["left_balance"]["value"] = json!(1_000_000);
            stale["channel"]["hub_balance"]["value"] = json!(0);
            stale["channel"]["deadline"]["value"] = json!(900_020);
        }
        let respond = HvmRegistryWatchtowerRequestV2 {
            schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
            operation_id: "registry-respond-1".into(),
            idempotency_key: "registry-respond-idempotency-1".into(),
            binding_commitment: binding_commitment.clone(),
            mode: HvmRegistryWatchtowerModeV2::Monitor,
            network_fee_zhu: 10_000,
            timestamp: now + 3,
            gas_max: u8::MAX,
            created_unix: now + 3,
        };
        let responded = hub.run_hvm_registry_watchtower(respond).await.unwrap();
        assert_eq!(responded.status, "confirmed");
        assert_eq!(responded.action, "respond");

        {
            let mut expired = live.write().await;
            expired["observed_height"] = json!(900_020);
            expired["evaluation_height"] = json!(900_021);
        }
        let finalize = HvmRegistryWatchtowerRequestV2 {
            schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
            operation_id: "registry-finalize-1".into(),
            idempotency_key: "registry-finalize-idempotency-1".into(),
            binding_commitment: binding_commitment.clone(),
            mode: HvmRegistryWatchtowerModeV2::Monitor,
            network_fee_zhu: 10_000,
            timestamp: now + 4,
            gas_max: u8::MAX,
            created_unix: now + 4,
        };
        let finalized = hub.run_hvm_registry_watchtower(finalize).await.unwrap();
        assert_eq!(finalized.status, "confirmed");
        assert_eq!(finalized.action, "finalize");
        assert_eq!(live.read().await["channel"]["status"]["value"], json!(4));

        let mut post_close = HvmRegistryPaymentRequestV2::build_unsigned(
            &network_binding(),
            &bundle.binding,
            &signed,
            "registry-payment-after-close",
            "registry-payment-after-close-idempotency",
            &bundle.binding.right_hub_address,
            1,
            now + 5,
            now + 305,
        )
        .unwrap();
        let hash = post_close
            .proposed_bill
            .signing_hash(&bundle.binding)
            .unwrap();
        post_close.proposed_bill.left_signature_hex =
            hex::encode(Sign::create_by(&left, &hash).serialize());
        let authorization_hash = post_close
            .payer_authorization_hash(&bundle.binding, &signed)
            .unwrap();
        post_close.payer_authorization_signature_hex =
            hex::encode(Sign::create_by(&left, &authorization_hash).serialize());
        assert!(
            hub.cosign_hvm_registry_payment(post_close, now + 5)
                .await
                .is_err(),
            "a finalized registry channel must never authorize another payment signature"
        );
    }

    let reopened = HubState::new_secure_with_policy(
        "registry integration",
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
    let renewal_status = reopened
        .hvm_registry_chain_operation_status(&confirmed_renewal_operation)
        .unwrap()
        .unwrap();
    assert_eq!(renewal_status.status, "confirmed");
    assert_eq!(
        reopened
            .hvm_registry_channel_status(&binding_commitment)
            .unwrap()
            .latest_fully_signed_bill,
        signed
    );
    assert_eq!(
        reopened
            .cosign_hvm_registry_payment(payment, now + 3)
            .await
            .unwrap(),
        signed
    );
    assert_eq!(
        submit_count.load(std::sync::atomic::Ordering::SeqCst),
        4,
        "restart must never sign or submit any additional lifecycle transaction"
    );
    server.abort();
}
