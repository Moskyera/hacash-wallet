//! Regression coverage for the classic L1 airgap transaction-type binding.

use std::collections::HashMap;

use axum::extract::Query;
use axum::routing::{get, post};
use axum::{Json, Router};
use basis::interface::Transaction;
use field::{Address, Amount, Serialize};
use hacash_wallet_core::{AirgapEnvelope, AirgapSigned, WalletService};
use protocol::action::HacToTrs;
use protocol::transaction::TransactionType2;
use serde_json::{Value, json};
use sys::ToHex;

const RECIPIENT: &str = "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS";
const SUBMITTED_HASH: &str = "airgap-type2-regression-hash";

async fn balance(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let address = query.get("address").cloned().unwrap_or_default();
    Json(json!({
        "ret": 0,
        "list": [{
            "address": address,
            "hacash": "1000",
            "satoshi": 0,
            "diamonds": ""
        }]
    }))
}

async fn fee_average() -> Json<Value> {
    Json(json!({
        "ret": 0,
        "feasible": "0.001",
        "purity": 1
    }))
}

async fn latest() -> Json<Value> {
    Json(json!({ "ret": 0, "height": 100, "diamond": 5 }))
}

async fn block_intro() -> Json<Value> {
    Json(json!({
        "ret": 0,
        "height": 1,
        "hash": hacash_wallet_core::node_discovery::MAINNET_BLOCK_ONE_HASH
    }))
}

async fn create_transaction(Json(payload): Json<Value>) -> Json<Value> {
    let result = (|| -> Result<String, String> {
        let main = payload
            .get("main_address")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing main_address".to_owned())
            .and_then(|value| Address::from_readable(value).map_err(|e| e.to_string()))?;
        let fee = payload
            .get("fee")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing fee".to_owned())
            .and_then(|value| Amount::from(value).map_err(|e| e.to_string()))?;
        let actions = payload
            .get("actions")
            .and_then(Value::as_array)
            .ok_or_else(|| "missing actions".to_owned())?;

        let mut tx = TransactionType2::new_by(main, fee, 1_700_000_000);
        for action_json in actions {
            let kind = action_json
                .get("kind")
                .and_then(Value::as_u64)
                .ok_or_else(|| "action kind missing".to_owned())?;
            let action = protocol::action::action_json_create(
                u16::try_from(kind).map_err(|_| "action kind overflow".to_owned())?,
                &action_json.to_string(),
            )
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("action kind {kind} is not registered"))?;
            tx.push_action(action).map_err(|e| e.to_string())?;
        }
        Ok(tx.serialize().to_hex())
    })();

    match result {
        Ok(body) => Json(json!({ "ret": 0, "body": body })),
        Err(error) => Json(json!({ "ret": 1, "err": error })),
    }
}

async fn submit_transaction(body: String) -> Json<Value> {
    assert!(
        !body.trim().is_empty(),
        "signed transaction body is required"
    );
    Json(json!({ "ret": 0, "hash": SUBMITTED_HASH }))
}

async fn spawn_node() -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/query/balance", get(balance))
        .route("/query/fee/average", get(fee_average))
        .route("/query/latest", get(latest))
        .route("/query/block/intro", get(block_intro))
        .route("/create/transaction", post(create_transaction))
        .route("/submit/transaction", post(submit_transaction));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock node");
    let address = listener.local_addr().expect("mock node address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve mock node");
    });
    (format!("http://{address}"), server)
}

fn build_type2_hac_body(from: &str, fee: &str, transfers: &[(&str, &str)]) -> String {
    let main = Address::from_readable(from).expect("sender address");
    let fee = Amount::from(fee).expect("network fee");
    let mut tx = TransactionType2::new_by(main, fee, 1_700_000_001);
    for (to, amount) in transfers {
        let to = Address::from_readable(to).expect("recipient address");
        let amount = Amount::from(amount).expect("transfer amount");
        tx.push_action(Box::new(HacToTrs::create_by(to, amount)))
            .expect("append HAC transfer");
    }
    tx.serialize().to_hex()
}

fn assert_amount_binding_error(error: hacash_wallet_core::WalletError) {
    assert!(
        error.to_string().contains("amount metadata"),
        "unexpected air-gap rejection: {error}"
    );
}

#[tokio::test]
async fn classic_l1_airgap_prepare_sign_and_broadcast_uses_consensus_type2() {
    let data = tempfile::tempdir().expect("isolated wallet data");
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", data.path());
    }
    let (node_url, server) = spawn_node().await;
    let mut wallet = WalletService::new(Some(node_url), None).expect("wallet service");
    wallet
        .create_wallet("airgap-istanbul-regression-passphrase")
        .expect("create wallet");

    let prepared = wallet
        .prepare_airgap_l1_send(RECIPIENT, 1.0)
        .await
        .expect("prepare classic L1 airgap send");
    assert_eq!(prepared.envelope.tx_type, 2);

    let signed = wallet
        .sign_airgap_unsigned(&prepared.envelope)
        .expect("sign classic L1 airgap send");
    assert_eq!(signed.envelope.tx_type, 2);

    let submitted = wallet
        .broadcast_airgap_signed(&signed.envelope)
        .await
        .expect("broadcast classic L1 airgap send");
    assert_eq!(submitted.tx_hash, SUBMITTED_HASH);

    let attacker_amount = "500";
    let wallet_fee_wire = hacash_wallet_core::send_options::format_service_fee_amount_wire(
        prepared.envelope.service_fee_mei,
    );
    let forged_body = build_type2_hac_body(
        &prepared.envelope.from,
        &prepared.envelope.fee,
        &[
            (RECIPIENT, attacker_amount),
            (
                hacash_wallet_core::WALLET_TREASURY_ADDRESS,
                &wallet_fee_wire,
            ),
        ],
    );
    let mut forged_unsigned = prepared.envelope.clone();
    forged_unsigned.amount_wire = attacker_amount.into();
    forged_unsigned.body_hex = forged_body.clone();
    forged_unsigned.summary = format!("Send {attacker_amount} HAC to {RECIPIENT}");
    assert_amount_binding_error(
        wallet
            .sign_airgap_unsigned(&forged_unsigned)
            .expect_err("small displayed amount must not authorize a larger body transfer"),
    );

    let forged_signed = AirgapSigned {
        v: forged_unsigned.v,
        tx_type: forged_unsigned.tx_type,
        from: forged_unsigned.from.clone(),
        to: forged_unsigned.to.clone(),
        amount_mei: forged_unsigned.amount_mei,
        amount_wire: forged_unsigned.amount_wire.clone(),
        fee: forged_unsigned.fee.clone(),
        service_fee_mei: forged_unsigned.service_fee_mei,
        service_fee_treasury: forged_unsigned.service_fee_treasury.clone(),
        signed_hex: forged_body,
        summary: forged_unsigned.summary.clone(),
    };
    assert_amount_binding_error(
        wallet
            .broadcast_airgap_signed(&forged_signed)
            .await
            .expect_err("broadcast must independently enforce the canonical amount"),
    );

    let mut forged_summary = prepared.envelope.clone();
    forged_summary.summary = "Receive a harmless verification payment".into();
    let inspection = wallet
        .inspect_airgap_envelope(&AirgapEnvelope::Unsigned(forged_summary))
        .expect("valid body must produce a canonical inspection");
    assert_eq!(
        inspection.summary,
        format!("Send {} HAC to {RECIPIENT}", prepared.envelope.amount_wire)
    );

    let forged_recipient = Address::create_privakey([0x42; 20]).to_readable();
    let mut recipient_swap = prepared.envelope.clone();
    recipient_swap.to = forged_recipient.clone();
    recipient_swap.summary = format!(
        "Send {} HAC to {forged_recipient}",
        recipient_swap.amount_wire
    );
    let recipient_error = wallet
        .inspect_airgap_envelope(&AirgapEnvelope::Unsigned(recipient_swap))
        .expect_err("displayed recipient must match the recipient in the body");
    assert!(
        recipient_error
            .to_string()
            .contains("differs from the approved request"),
        "unexpected recipient rejection: {recipient_error}"
    );

    server.abort();
    unsafe {
        std::env::remove_var("HACASH_WALLET_DATA");
    }
}
