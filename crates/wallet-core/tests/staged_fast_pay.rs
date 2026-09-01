use axum::{Json, Router, routing::get};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::bills::BillStore;
use hacash_wallet_core::channel::{
    CHANNEL_STATUS_OPENING, ChannelInfo, ChannelPartyBalance, derive_channel_id,
};
use hacash_wallet_core::l2_hub::{FastPayRequest, L2HubClient};
use hacash_wallet_core::l2_safety::{ClientL2Safety, ClientOperationStatus};
use l2_fast_pay_hub::amount::HacAmount;
use l2_fast_pay_hub::node::{
    ChannelInfo as WireChannelInfo, ChannelPartyBalance as WireChannelPartyBalance, ChannelSide,
};
use l2_fast_pay_hub::wire::{ChannelWireInput, build_same_channel_bill};

#[test]
fn final_signing_revalidation_rejects_a_bill_stale_against_latest_local_state() {
    let root = tempfile::tempdir().unwrap();
    let payer = WalletAccount::create("staged-fast-pay-payer").unwrap();
    let hub = WalletAccount::create("staged-fast-pay-hub").unwrap();
    let channel_id = derive_channel_id(&payer.address(), &hub.address(), 1);
    let wire_channel = WireChannelInfo {
        ret: 0,
        id: channel_id.clone(),
        status: CHANNEL_STATUS_OPENING,
        open_height: 100,
        close_height: 0,
        reuse_version: 1,
        left: WireChannelPartyBalance {
            address: payer.address(),
            hacash: "10".to_owned(),
            satoshi: 0,
        },
        right: WireChannelPartyBalance {
            address: hub.address(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    let mut document = build_same_channel_bill(
        &ChannelWireInput {
            channel: wire_channel,
            channel_id_hex: channel_id.clone(),
            left_balance_mei: HacAmount::from_millimeis(9_000),
            right_balance_mei: HacAmount::from_millimeis(1_000),
            left_satoshi: 0,
            right_satoshi: 0,
            bill_auto_number: 1,
        },
        ChannelSide::Left,
        HacAmount::from_millimeis(1_000),
        1_700_000_000,
    )
    .unwrap();
    document
        .chain_payment
        .fill_sign_by_account(hub.inner())
        .unwrap();
    let unsigned = document.to_bill_hex();

    let scope = format!("personal:{}", payer.address());
    let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
        &payer,
        root.path().join("l2"),
        &scope,
        "testnet",
        &hub.address(),
        &channel_id,
    )
    .unwrap();
    let operation = safety
        .begin_or_resume(&payer.address(), &hub.address(), "1", 1_000, 1)
        .unwrap();
    safety
        .persist_before_signing(&operation.operation_id, &unsigned)
        .unwrap();

    document
        .chain_payment
        .fill_sign_by_account(payer.inner())
        .unwrap();
    let mut bills = BillStore::load_at(root.path().join("bills.json")).unwrap();
    bills
        .store_bill("already-committed-payment", &document.to_bill_hex())
        .unwrap();
    let channel = ChannelInfo {
        ret: 0,
        id: channel_id.clone(),
        status: CHANNEL_STATUS_OPENING,
        open_height: 100,
        close_height: 0,
        reuse_version: 1,
        arbitration_lock: 5_000,
        left: ChannelPartyBalance {
            address: payer.address(),
            hacash: "10".to_owned(),
            satoshi: 0,
        },
        right: ChannelPartyBalance {
            address: hub.address(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    let request = FastPayRequest {
        operation_id: operation.operation_id,
        idempotency_key: operation.idempotency_key,
        payer: payer.address(),
        payee: hub.address(),
        amount: "1".to_owned(),
        channel_id,
        fee_payer: Some("sender".to_owned()),
    };
    let error = L2HubClient::new_for_network("http://127.0.0.1:1", "testnet")
        .revalidate_persisted_sender_bill(&request, &bills, &safety, &channel, &hub.address())
        .unwrap_err();
    assert!(error.to_string().contains("bill number must be 2"));
}

#[tokio::test]
async fn pending_reconciliation_requires_explicit_retry_of_the_same_signed_bytes() {
    let root = tempfile::tempdir().unwrap();
    let payer = WalletAccount::create("reconcile-fast-pay-payer").unwrap();
    let hub = WalletAccount::create("reconcile-fast-pay-hub").unwrap();
    let channel_id = derive_channel_id(&payer.address(), &hub.address(), 1);
    let wire_channel = WireChannelInfo {
        ret: 0,
        id: channel_id.clone(),
        status: CHANNEL_STATUS_OPENING,
        open_height: 100,
        close_height: 0,
        reuse_version: 1,
        left: WireChannelPartyBalance {
            address: payer.address(),
            hacash: "10".to_owned(),
            satoshi: 0,
        },
        right: WireChannelPartyBalance {
            address: hub.address(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    let mut document = build_same_channel_bill(
        &ChannelWireInput {
            channel: wire_channel,
            channel_id_hex: channel_id.clone(),
            left_balance_mei: HacAmount::from_millimeis(9_000),
            right_balance_mei: HacAmount::from_millimeis(1_000),
            left_satoshi: 0,
            right_satoshi: 0,
            bill_auto_number: 1,
        },
        ChannelSide::Left,
        HacAmount::from_millimeis(1_000),
        1_700_000_000,
    )
    .unwrap();
    document
        .chain_payment
        .fill_sign_by_account(hub.inner())
        .unwrap();
    let unsigned = document.to_bill_hex();
    document
        .chain_payment
        .fill_sign_by_account(payer.inner())
        .unwrap();
    let signed = document.to_bill_hex();

    let scope = format!("personal:{}", payer.address());
    let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
        &payer,
        root.path().join("l2"),
        &scope,
        "testnet",
        &hub.address(),
        &channel_id,
    )
    .unwrap();
    let operation = safety
        .begin_or_resume(&payer.address(), &hub.address(), "1", 1_000, 1)
        .unwrap();
    safety
        .persist_before_signing(&operation.operation_id, &unsigned)
        .unwrap();
    safety
        .persist_signature(&operation.operation_id, &signed)
        .unwrap();
    let request = FastPayRequest {
        operation_id: operation.operation_id.clone(),
        idempotency_key: operation.idempotency_key,
        payer: payer.address(),
        payee: hub.address(),
        amount: "1".to_owned(),
        channel_id: channel_id.clone(),
        fee_payer: Some("sender".to_owned()),
    };
    let channel = ChannelInfo {
        ret: 0,
        id: channel_id,
        status: CHANNEL_STATUS_OPENING,
        open_height: 100,
        close_height: 0,
        reuse_version: 1,
        arbitration_lock: 5_000,
        left: ChannelPartyBalance {
            address: payer.address(),
            hacash: "10".to_owned(),
            satoshi: 0,
        },
        right: ChannelPartyBalance {
            address: hub.address(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    let mut bills = BillStore::load_at(root.path().join("bills.json")).unwrap();

    let pending_response = serde_json::json!({
        "payment_id": request.operation_id,
        "status": "pending",
        "bill_hex": unsigned,
        "summary": "pending"
    });
    let app = Router::new().route(
        "/v1/fast-pay/{payment_id}",
        get(move || {
            let response = pending_response.clone();
            async move { Json(response) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let pending_hub = L2HubClient::new_for_network(format!("http://{address}"), "testnet");
    let pending = pending_hub
        .reconcile_sender_bill(&request, &mut bills, &mut safety, &channel, &hub.address())
        .await
        .unwrap();
    assert_eq!(pending.status, "pending");
    assert_eq!(
        safety.operation(&operation.operation_id).unwrap().status,
        ClientOperationStatus::RecoveryRequired
    );
    assert_eq!(bills.count(), 0);
    server.abort();

    let retry_pending_response = serde_json::json!({
        "payment_id": request.operation_id,
        "status": "pending",
        "bill_hex": unsigned,
        "summary": "pending"
    });
    let settled_response = serde_json::json!({
        "payment_id": request.operation_id,
        "status": "settled",
        "bill_hex": signed,
        "summary": "settled"
    });
    let expected_signed = signed.clone();
    let app = Router::new()
        .route(
            "/v1/fast-pay/{payment_id}",
            get(move || {
                let response = retry_pending_response.clone();
                async move { Json(response) }
            }),
        )
        .route(
            "/v1/fast-pay/{payment_id}/confirm",
            axum::routing::post(move |Json(body): Json<serde_json::Value>| {
                let response = settled_response.clone();
                let expected_signed = expected_signed.clone();
                async move {
                    assert_eq!(
                        body.get("bill_hex").and_then(serde_json::Value::as_str),
                        Some(expected_signed.as_str())
                    );
                    Json(response)
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let retry_hub = L2HubClient::new_for_network(format!("http://{address}"), "testnet");
    let settled = retry_hub
        .retry_reconciled_sender_bill(&request, &mut bills, &mut safety, &channel, &hub.address())
        .await
        .unwrap();
    assert_eq!(settled.status, "settled");
    assert_eq!(
        safety.operation(&operation.operation_id).unwrap().status,
        ClientOperationStatus::Committed
    );
    assert_eq!(
        bills.get_bill(&operation.operation_id),
        Some(signed.as_str())
    );
    server.abort();
}

#[tokio::test]
async fn lost_prepare_response_recovers_only_the_exact_unsigned_hub_bill() {
    let root = tempfile::tempdir().unwrap();
    let payer = WalletAccount::create("unsigned-recovery-payer").unwrap();
    let hub = WalletAccount::create("unsigned-recovery-hub").unwrap();
    let channel_id = derive_channel_id(&payer.address(), &hub.address(), 1);
    let wire_channel = WireChannelInfo {
        ret: 0,
        id: channel_id.clone(),
        status: CHANNEL_STATUS_OPENING,
        open_height: 100,
        close_height: 0,
        reuse_version: 1,
        left: WireChannelPartyBalance {
            address: payer.address(),
            hacash: "10".to_owned(),
            satoshi: 0,
        },
        right: WireChannelPartyBalance {
            address: hub.address(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    let mut document = build_same_channel_bill(
        &ChannelWireInput {
            channel: wire_channel,
            channel_id_hex: channel_id.clone(),
            left_balance_mei: HacAmount::from_millimeis(9_000),
            right_balance_mei: HacAmount::from_millimeis(1_000),
            left_satoshi: 0,
            right_satoshi: 0,
            bill_auto_number: 1,
        },
        ChannelSide::Left,
        HacAmount::from_millimeis(1_000),
        1_700_000_000,
    )
    .unwrap();
    document
        .chain_payment
        .fill_sign_by_account(hub.inner())
        .unwrap();
    let unsigned = document.to_bill_hex();
    let scope = format!("personal:{}", payer.address());
    let mut safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
        &payer,
        root.path().join("l2"),
        &scope,
        "testnet",
        &hub.address(),
        &channel_id,
    )
    .unwrap();
    let operation = safety
        .begin_or_resume(&payer.address(), &hub.address(), "1", 1_000, 1)
        .unwrap();
    safety
        .mark_recovery_required(&operation.operation_id)
        .unwrap();
    let request = FastPayRequest {
        operation_id: operation.operation_id.clone(),
        idempotency_key: operation.idempotency_key,
        payer: payer.address(),
        payee: hub.address(),
        amount: "1".to_owned(),
        channel_id: channel_id.clone(),
        fee_payer: Some("sender".to_owned()),
    };
    let channel = ChannelInfo {
        ret: 0,
        id: channel_id,
        status: CHANNEL_STATUS_OPENING,
        open_height: 100,
        close_height: 0,
        reuse_version: 1,
        arbitration_lock: 5_000,
        left: ChannelPartyBalance {
            address: payer.address(),
            hacash: "10".to_owned(),
            satoshi: 0,
        },
        right: ChannelPartyBalance {
            address: hub.address(),
            hacash: "0".to_owned(),
            satoshi: 0,
        },
        challenging: None,
    };
    let pending_response = serde_json::json!({
        "payment_id": request.operation_id,
        "status": "pending",
        "bill_hex": unsigned,
        "summary": "pending"
    });
    let app = Router::new().route(
        "/v1/fast-pay/{payment_id}",
        get(move || {
            let response = pending_response.clone();
            async move { Json(response) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let bills = BillStore::load_at(root.path().join("bills.json")).unwrap();
    let recovered = L2HubClient::new_for_network(format!("http://{address}"), "testnet")
        .reconcile_unsigned_sender_bill(&request, &bills, &mut safety, &channel, &hub.address())
        .await
        .unwrap();
    assert_eq!(
        recovered.status,
        ClientOperationStatus::PersistedBeforeSigning
    );
    assert_eq!(
        recovered.unsigned_bill_hex.as_deref(),
        Some(unsigned.as_str())
    );
    assert!(recovered.signed_bill_hex.is_none());
    server.abort();
}
