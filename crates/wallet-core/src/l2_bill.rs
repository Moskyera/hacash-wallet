use basis::method::verify_signature;
use chrono::{TimeZone, Utc};
use l2_fast_pay_hub::wire::ChannelPayCompleteDocuments;
use l2_fast_pay_hub::wire::{DIRECTION_LEFT_TO_RIGHT, DIRECTION_RIGHT_TO_LEFT};
use field::Hex;
use serde::{Deserialize, Serialize};
use sys::Account;

use crate::account::WalletAccount;
use crate::bills::BillEntry;
use crate::error::{WalletError, WalletResult};

const EXPORT_VERSION: u32 = 1;

/// Parse hub bill, co-sign payer slot, return updated hex.
pub fn cosign_bill_hex(bill_hex: &str, account: &WalletAccount) -> WalletResult<String> {
    let mut doc = parse_bill_hex(bill_hex)?;
    let sign = doc
        .chain_payment
        .fill_sign_by_account(account.inner())
        .map_err(|e| WalletError::L2(e.to_string()))?;
    verify_payer_sign(&doc.chain_payment.sign_stuff_hash(), account.inner(), &sign)?;
    Ok(doc.to_bill_hex())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillProveSummary {
    pub channel_id_hex: String,
    pub bill_auto_number: u64,
    pub pay_amount_mei: String,
    pub pay_direction: String,
    pub left_balance_mei: String,
    pub right_balance_mei: String,
    pub left_address: String,
    pub right_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillSignatureStatus {
    pub address: String,
    pub filled: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillSummary {
    pub payment_id: String,
    pub timestamp_unix: u64,
    pub timestamp_utc: String,
    pub channel_legs: u8,
    pub hex_byte_length: usize,
    pub prove_bodies: Vec<BillProveSummary>,
    pub signatures: Vec<BillSignatureStatus>,
    pub all_signatures_filled: bool,
    pub all_signatures_verified: bool,
    /// True when every required signature verifies — safe for channel dispute submission.
    pub dispute_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillExportBundle {
    pub export_version: u32,
    pub exported_at_utc: String,
    pub wallet_note: String,
    pub bill_count: usize,
    pub bills: Vec<BillExportItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillExportItem {
    pub payment_id: String,
    pub bill_hex: String,
    pub summary: BillSummary,
}

pub fn summarize_bill(payment_id: &str, bill_hex: &str) -> WalletResult<BillSummary> {
    let doc = parse_bill_hex(bill_hex)?;
    let chain = &doc.chain_payment;
    let hash = chain.sign_stuff_hash();
    let empty_pk = field::Fixed33::default().to_array();

    let signatures = chain
        .must_sign_addresses
        .iter()
        .zip(chain.must_signs.iter())
        .map(|(addr, sign)| {
            let filled = sign.publickey.to_array() != empty_pk;
            let verified = filled && verify_signature(&hash, addr, sign);
            BillSignatureStatus {
                address: addr.to_readable(),
                filled,
                verified,
            }
        })
        .collect::<Vec<_>>();

    let all_signatures_filled = chain.all_slots_filled();
    let all_signatures_verified = signatures.iter().all(|s| s.verified);
    let timestamp_unix = chain.timestamp.uint();

    Ok(BillSummary {
        payment_id: payment_id.to_owned(),
        timestamp_unix,
        timestamp_utc: format_timestamp(timestamp_unix),
        channel_legs: *chain.channel_count,
        hex_byte_length: bill_hex.len() / 2,
        prove_bodies: doc
            .prove_bodies
            .iter()
            .map(|body| BillProveSummary {
                channel_id_hex: body.channel_id.to_hex(),
                bill_auto_number: *body.bill_auto_number as u64,
                pay_amount_mei: body.pay_amount.to_unit_string("mei"),
                pay_direction: direction_label(*body.pay_direction),
                left_balance_mei: body.left_balance.to_unit_string("mei"),
                right_balance_mei: body.right_balance.to_unit_string("mei"),
                left_address: body.left_address.to_readable(),
                right_address: body.right_address.to_readable(),
            })
            .collect(),
        all_signatures_filled,
        all_signatures_verified,
        dispute_ready: all_signatures_filled && all_signatures_verified,
        signatures,
    })
}

pub fn export_bill_item(entry: &BillEntry) -> WalletResult<BillExportItem> {
    Ok(BillExportItem {
        payment_id: entry.payment_id.clone(),
        bill_hex: entry.bill_hex.clone(),
        summary: summarize_bill(&entry.payment_id, &entry.bill_hex)?,
    })
}

pub fn export_all_bills(entries: &[BillEntry]) -> WalletResult<BillExportBundle> {
    let bills = entries
        .iter()
        .map(export_bill_item)
        .collect::<WalletResult<Vec<_>>>()?;
    Ok(BillExportBundle {
        export_version: EXPORT_VERSION,
        exported_at_utc: Utc::now().to_rfc3339(),
        wallet_note: "Hacash L2 Fast Pay settlement bills — submit bill_hex with channel challenge if disputed.".into(),
        bill_count: bills.len(),
        bills,
    })
}

pub fn export_bill_json(entry: &BillEntry) -> WalletResult<String> {
    let item = export_bill_item(entry)?;
    serde_json::to_string_pretty(&item).map_err(|e| WalletError::L2(e.to_string()))
}

pub fn export_all_bills_json(entries: &[BillEntry]) -> WalletResult<String> {
    let bundle = export_all_bills(entries)?;
    serde_json::to_string_pretty(&bundle).map_err(|e| WalletError::L2(e.to_string()))
}

fn parse_bill_hex(bill_hex: &str) -> WalletResult<ChannelPayCompleteDocuments> {
    ChannelPayCompleteDocuments::from_bill_hex(bill_hex).map_err(|e| WalletError::L2(e.to_string()))
}

fn verify_payer_sign(
    hash: &field::Hash,
    account: &Account,
    sign: &field::Sign,
) -> WalletResult<()> {
    let addr = field::Address::from(*account.address());
    if !verify_signature(hash, &addr, sign) {
        return Err(WalletError::L2("payer bill signature verification failed".into()));
    }
    Ok(())
}

fn direction_label(dir: u8) -> String {
    match dir {
        DIRECTION_LEFT_TO_RIGHT => "left_to_right".into(),
        DIRECTION_RIGHT_TO_LEFT => "right_to_left".into(),
        other => format!("unknown({other})"),
    }
}

fn format_timestamp(ts: u64) -> String {
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_fast_pay_hub::channel_id::derive_channel_id;
    use l2_fast_pay_hub::node::{ChannelInfo, ChannelPartyBalance};
    use l2_fast_pay_hub::wire::{build_same_channel_bill, ChannelWireInput};
    use sys::Account;

    fn sample_channel(id: &str, left: &str, right: &str, left_mei: &str) -> ChannelInfo {
        ChannelInfo {
            ret: 0,
            id: id.to_owned(),
            status: 0,
            reuse_version: 1,
            left: ChannelPartyBalance {
                address: left.into(),
                hacash: left_mei.into(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: right.into(),
                hacash: "1".into(),
                satoshi: 0,
            },
            challenging: None,
        }
    }

    #[test]
    fn summarize_signed_bill_marks_dispute_ready() {
        let alice = Account::create_by("alice-bill-summary").unwrap();
        let hub = Account::create_by("hub-bill-summary").unwrap();
        let channel_id = derive_channel_id(alice.readable(), hub.readable(), 1);
        let mut doc = build_same_channel_bill(
            &ChannelWireInput {
                channel: sample_channel(&channel_id, alice.readable(), hub.readable(), "5"),
                channel_id_hex: channel_id,
                left_balance_mei: 4.0,
                right_balance_mei: 2.0,
                left_satoshi: 0,
                right_satoshi: 0,
                bill_auto_number: 1,
            },
            1.0,
            1_700_000_000,
        )
        .unwrap();
        doc.chain_payment.fill_sign_by_account(&alice).unwrap();
        doc.chain_payment.fill_sign_by_account(&hub).unwrap();
        let hex = doc.to_bill_hex();
        let summary = summarize_bill("pay-test-1", &hex).unwrap();
        assert!(summary.dispute_ready);
        assert_eq!(summary.prove_bodies.len(), 1);
        assert_eq!(summary.signatures.len(), 2);
    }
}