use std::collections::BTreeSet;

use basis::method::verify_signature;
use chrono::{TimeZone, Utc};
use field::{Amount, Hex};
use l2_fast_pay_hub::wire::ChannelPayCompleteDocuments;
use l2_fast_pay_hub::wire::TransferProveBody;
use l2_fast_pay_hub::wire::{DIRECTION_LEFT_TO_RIGHT, DIRECTION_RIGHT_TO_LEFT};
use serde::{Deserialize, Serialize};
use sys::Account;

use crate::account::WalletAccount;
use crate::bills::{BillEntry, BillStore};
use crate::channel::ChannelInfo;
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
    /// True when every required signature verifies. safe for channel dispute submission.
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

#[derive(Clone)]
pub(crate) struct TrustedChannelState {
    pub channel_id_hex: String,
    pub reuse_version: u64,
    pub bill_auto_number: u64,
    pub left_address: String,
    pub right_address: String,
    pub left_balance: Amount,
    pub right_balance: Amount,
    pub left_satoshi: u64,
    pub right_satoshi: u64,
}

pub(crate) fn trusted_channel_state(
    bills: &BillStore,
    channel: &ChannelInfo,
) -> WalletResult<TrustedChannelState> {
    let mut state = TrustedChannelState {
        channel_id_hex: channel.id.to_ascii_lowercase(),
        reuse_version: channel.reuse_version,
        bill_auto_number: 0,
        left_address: channel.left.address.clone(),
        right_address: channel.right.address.clone(),
        left_balance: parse_mei_amount(&channel.left.hacash, "on-chain left balance")?,
        right_balance: parse_mei_amount(&channel.right.hacash, "on-chain right balance")?,
        left_satoshi: channel.left.satoshi,
        right_satoshi: channel.right.satoshi,
    };

    for entry in bills.list() {
        let Ok(doc) = parse_bill_hex(&entry.bill_hex) else {
            continue;
        };
        if !doc.prove_bindings_valid() || !doc.chain_payment.all_signatures_verified() {
            continue;
        }
        for body in &doc.prove_bodies {
            let bill_number = *body.bill_auto_number as u64;
            if body
                .channel_id
                .to_hex()
                .eq_ignore_ascii_case(&state.channel_id_hex)
                && *body.reuse_version as u64 == state.reuse_version
                && body.left_address.to_readable() == state.left_address
                && body.right_address.to_readable() == state.right_address
                && bill_number > state.bill_auto_number
            {
                state.bill_auto_number = bill_number;
                state.left_balance = body.left_balance.clone();
                state.right_balance = body.right_balance.clone();
                state.left_satoshi = body_left_satoshi(body);
                state.right_satoshi = body_right_satoshi(body);
            }
        }
    }

    let challenge_floor = channel
        .challenging
        .as_ref()
        .map(|challenge| challenge.assert_bill_auto_number)
        .unwrap_or(0);
    if challenge_floor > state.bill_auto_number {
        return Err(WalletError::Policy(format!(
            "channel has on-chain challenge bill {challenge_floor}, but the wallet only trusts bill {}; import the latest signed bill before Fast Pay",
            state.bill_auto_number
        )));
    }
    Ok(state)
}

pub(crate) fn validate_sender_bill(
    payment_id: &str,
    bill_hex: &str,
    payer: &str,
    payee: &str,
    amount_wire: &str,
    hub_address: &str,
    payer_channel_id: &str,
    trusted: &TrustedChannelState,
) -> WalletResult<BillSummary> {
    let doc = parse_bill_hex(bill_hex)?;
    let cross_channel = payee != hub_address;
    let expected_legs = if cross_channel { 2 } else { 1 };
    let expected_signers = if cross_channel {
        vec![payer, payee, hub_address]
    } else {
        vec![payer, hub_address]
    };
    validate_bill_shell(&doc, &expected_signers, expected_legs, hub_address)?;

    if !trusted
        .channel_id_hex
        .eq_ignore_ascii_case(payer_channel_id)
    {
        return Err(WalletError::Policy(
            "Fast Pay payer channel does not match the locally trusted channel".into(),
        ));
    }
    let amount = parse_mei_amount(amount_wire, "Fast Pay amount")?;
    if amount.is_zero() || amount.is_negative() {
        return Err(WalletError::Policy(
            "Fast Pay amount must be positive".into(),
        ));
    }

    let mut payer_legs = doc.prove_bodies.iter().filter(|body| {
        body.channel_id
            .to_hex()
            .eq_ignore_ascii_case(payer_channel_id)
    });
    let payer_leg = payer_legs.next().ok_or_else(|| {
        WalletError::Policy("Fast Pay bill is missing the payer channel leg".into())
    })?;
    if payer_legs.next().is_some() {
        return Err(WalletError::Policy(
            "Fast Pay bill contains duplicate payer channel legs".into(),
        ));
    }
    validate_trusted_leg(payer_leg, trusted, payer, hub_address, &amount, false)?;

    if cross_channel {
        let other = doc
            .prove_bodies
            .iter()
            .find(|body| !std::ptr::eq(*body, payer_leg))
            .ok_or_else(|| {
                WalletError::Policy("Fast Pay bill is missing the recipient leg".into())
            })?;
        if other
            .channel_id
            .to_hex()
            .eq_ignore_ascii_case(payer_channel_id)
        {
            return Err(WalletError::Policy(
                "Fast Pay routed legs must use different channels".into(),
            ));
        }
        validate_other_leg(other, payee, hub_address, &amount, true, None)?;
    }

    summarize_bill(payment_id, bill_hex)
}

pub(crate) fn validate_recipient_bill(
    payment_id: &str,
    bill_hex: &str,
    payer: &str,
    payee: &str,
    amount_wire: &str,
    hub_address: &str,
    payer_channel_id: &str,
    payee_channel_id: &str,
    trusted: &TrustedChannelState,
) -> WalletResult<BillSummary> {
    let doc = parse_bill_hex(bill_hex)?;
    validate_bill_shell(&doc, &[payer, payee, hub_address], 2, hub_address)?;
    if !doc.chain_payment.signature_verified_for_readable(payer) {
        return Err(WalletError::Policy(
            "Fast Pay request is missing the verified payer signature".into(),
        ));
    }
    if payee == payer || payee == hub_address || payer == hub_address {
        return Err(WalletError::Policy(
            "Fast Pay routed parties must be three different addresses".into(),
        ));
    }
    if !trusted
        .channel_id_hex
        .eq_ignore_ascii_case(payee_channel_id)
        || payer_channel_id.eq_ignore_ascii_case(payee_channel_id)
    {
        return Err(WalletError::Policy(
            "Fast Pay recipient channel binding is invalid".into(),
        ));
    }

    let amount = parse_mei_amount(amount_wire, "Fast Pay amount")?;
    if amount.is_zero() || amount.is_negative() {
        return Err(WalletError::Policy(
            "Fast Pay amount must be positive".into(),
        ));
    }

    let payee_leg = doc
        .prove_bodies
        .iter()
        .find(|body| {
            body.channel_id
                .to_hex()
                .eq_ignore_ascii_case(payee_channel_id)
        })
        .ok_or_else(|| {
            WalletError::Policy("Fast Pay bill is missing the recipient channel leg".into())
        })?;
    let payer_leg = doc
        .prove_bodies
        .iter()
        .find(|body| {
            body.channel_id
                .to_hex()
                .eq_ignore_ascii_case(payer_channel_id)
        })
        .ok_or_else(|| {
            WalletError::Policy("Fast Pay bill is missing the payer channel leg".into())
        })?;
    if std::ptr::eq(payee_leg, payer_leg) {
        return Err(WalletError::Policy(
            "Fast Pay routed legs must use different channels".into(),
        ));
    }

    validate_trusted_leg(payee_leg, trusted, payee, hub_address, &amount, true)?;
    validate_other_leg(
        payer_leg,
        payer,
        hub_address,
        &amount,
        false,
        Some(payer_channel_id),
    )?;
    summarize_bill(payment_id, bill_hex)
}

fn validate_bill_shell(
    doc: &ChannelPayCompleteDocuments,
    expected_signers: &[&str],
    expected_legs: usize,
    hub_address: &str,
) -> WalletResult<()> {
    if !doc.prove_bindings_valid()
        || doc.prove_bodies.len() != expected_legs
        || *doc.chain_payment.channel_count as usize != expected_legs
        || *doc.chain_payment.must_sign_count as usize
            != doc.chain_payment.must_sign_addresses.len()
        || doc.chain_payment.must_sign_addresses.len() != doc.chain_payment.must_signs.len()
    {
        return Err(WalletError::Policy(
            "Fast Pay bill structure or prove bindings are invalid".into(),
        ));
    }
    if !doc.chain_payment.all_filled_signatures_verified() {
        return Err(WalletError::Policy(
            "Fast Pay bill contains an invalid signature".into(),
        ));
    }

    let actual = doc
        .chain_payment
        .must_sign_addresses
        .iter()
        .map(|address| address.to_readable())
        .collect::<BTreeSet<_>>();
    let expected = expected_signers
        .iter()
        .map(|address| (*address).to_owned())
        .collect::<BTreeSet<_>>();
    if actual != expected || actual.len() != expected_signers.len() {
        return Err(WalletError::Policy(
            "Fast Pay bill required-signature set does not match the payment parties".into(),
        ));
    }
    if !doc
        .chain_payment
        .signature_verified_for_readable(hub_address)
    {
        return Err(WalletError::Policy(
            "Fast Pay bill is missing the verified hub signature".into(),
        ));
    }
    Ok(())
}

fn validate_trusted_leg(
    body: &TransferProveBody,
    trusted: &TrustedChannelState,
    user: &str,
    hub: &str,
    amount: &Amount,
    credit_user: bool,
) -> WalletResult<()> {
    if !body
        .channel_id
        .to_hex()
        .eq_ignore_ascii_case(&trusted.channel_id_hex)
        || *body.reuse_version as u64 != trusted.reuse_version
        || body.left_address.to_readable() != trusted.left_address
        || body.right_address.to_readable() != trusted.right_address
    {
        return Err(WalletError::Policy(
            "Fast Pay bill channel identity or parties do not match local trusted state".into(),
        ));
    }
    let expected_bill = trusted
        .bill_auto_number
        .checked_add(1)
        .ok_or_else(|| WalletError::Policy("Fast Pay bill number overflow".into()))?;
    if *body.bill_auto_number as u64 != expected_bill {
        return Err(WalletError::Policy(format!(
            "Fast Pay bill number must be {expected_bill}, got {}",
            *body.bill_auto_number as u64
        )));
    }
    if !amount_equal(&body.pay_amount, amount) || body.pay_satoshi.not_empty.as_ref()[0] != 0 {
        return Err(WalletError::Policy(
            "Fast Pay bill changes an unexpected HAC or BTC amount".into(),
        ));
    }
    if body_left_satoshi(body) != trusted.left_satoshi
        || body_right_satoshi(body) != trusted.right_satoshi
    {
        return Err(WalletError::Policy(
            "Fast Pay bill changes channel BTC balances during a HAC payment".into(),
        ));
    }

    let user_is_left = trusted.left_address == user && trusted.right_address == hub;
    let user_is_right = trusted.right_address == user && trusted.left_address == hub;
    if !user_is_left && !user_is_right {
        return Err(WalletError::Policy(
            "Fast Pay trusted channel is not between this wallet and the selected hub".into(),
        ));
    }

    let (expected_left, expected_right, expected_direction) = match (user_is_left, credit_user) {
        (true, false) => (
            checked_sub(&trusted.left_balance, amount, "payer channel balance")?,
            checked_add(&trusted.right_balance, amount)?,
            DIRECTION_LEFT_TO_RIGHT,
        ),
        (true, true) => (
            checked_add(&trusted.left_balance, amount)?,
            checked_sub(&trusted.right_balance, amount, "hub channel liquidity")?,
            DIRECTION_RIGHT_TO_LEFT,
        ),
        (false, false) => (
            checked_add(&trusted.left_balance, amount)?,
            checked_sub(&trusted.right_balance, amount, "payer channel balance")?,
            DIRECTION_RIGHT_TO_LEFT,
        ),
        (false, true) => (
            checked_sub(&trusted.left_balance, amount, "hub channel liquidity")?,
            checked_add(&trusted.right_balance, amount)?,
            DIRECTION_LEFT_TO_RIGHT,
        ),
    };
    if *body.pay_direction != expected_direction
        || !amount_equal(&body.left_balance, &expected_left)
        || !amount_equal(&body.right_balance, &expected_right)
    {
        return Err(WalletError::Policy(
            "Fast Pay bill post-payment balances do not exactly match the requested transfer"
                .into(),
        ));
    }
    Ok(())
}

fn validate_other_leg(
    body: &TransferProveBody,
    user: &str,
    hub: &str,
    amount: &Amount,
    credit_user: bool,
    expected_channel_id: Option<&str>,
) -> WalletResult<()> {
    if let Some(channel_id) = expected_channel_id {
        if !body.channel_id.to_hex().eq_ignore_ascii_case(channel_id) {
            return Err(WalletError::Policy(
                "Fast Pay bill channel binding does not match the request".into(),
            ));
        }
    }
    let left = body.left_address.to_readable();
    let right = body.right_address.to_readable();
    let user_is_left = left == user && right == hub;
    let user_is_right = right == user && left == hub;
    if !user_is_left && !user_is_right {
        return Err(WalletError::Policy(
            "Fast Pay routed leg parties do not match the payer, recipient, and hub".into(),
        ));
    }
    let expected_direction = match (user_is_left, credit_user) {
        (true, false) => DIRECTION_LEFT_TO_RIGHT,
        (true, true) => DIRECTION_RIGHT_TO_LEFT,
        (false, false) => DIRECTION_RIGHT_TO_LEFT,
        (false, true) => DIRECTION_LEFT_TO_RIGHT,
    };
    if *body.pay_direction != expected_direction
        || !amount_equal(&body.pay_amount, amount)
        || body.pay_satoshi.not_empty.as_ref()[0] != 0
        || body.left_balance.is_negative()
        || body.right_balance.is_negative()
        || *body.bill_auto_number == 0
    {
        return Err(WalletError::Policy(
            "Fast Pay routed leg amount, direction, or balances are invalid".into(),
        ));
    }
    Ok(())
}

fn parse_mei_amount(value: &str, label: &str) -> WalletResult<Amount> {
    Amount::from(value).map_err(|error| WalletError::Policy(format!("invalid {label}: {error}")))
}

fn checked_add(balance: &Amount, amount: &Amount) -> WalletResult<Amount> {
    balance
        .add_mode_bigint(amount)
        .map_err(|error| WalletError::Policy(format!("Fast Pay balance overflow: {error}")))
}

fn checked_sub(balance: &Amount, amount: &Amount, label: &str) -> WalletResult<Amount> {
    if balance.to_bigint() < amount.to_bigint() {
        return Err(WalletError::Policy(format!(
            "insufficient {label} for Fast Pay"
        )));
    }
    balance
        .sub_mode_bigint(amount)
        .map_err(|error| WalletError::Policy(format!("Fast Pay balance underflow: {error}")))
}

fn amount_equal(left: &Amount, right: &Amount) -> bool {
    left.to_bigint() == right.to_bigint()
}

fn body_left_satoshi(body: &TransferProveBody) -> u64 {
    if body.left_satoshi.not_empty.as_ref()[0] == 1 {
        *body.left_satoshi.value_sat
    } else {
        0
    }
}

fn body_right_satoshi(body: &TransferProveBody) -> u64 {
    if body.right_satoshi.not_empty.as_ref()[0] == 1 {
        *body.right_satoshi.value_sat
    } else {
        0
    }
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
        wallet_note: "Hacash L2 Fast Pay settlement bills. submit bill_hex with channel challenge if disputed.".into(),
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
        return Err(WalletError::L2(
            "payer bill signature verification failed".into(),
        ));
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
    use l2_fast_pay_hub::node::{ChannelInfo, ChannelPartyBalance, ChannelSide};
    use l2_fast_pay_hub::wire::{
        ChannelWireInput, build_cross_channel_bill, build_same_channel_bill,
    };
    use sys::Account;

    fn sample_channel(
        id: &str,
        left: &str,
        right: &str,
        left_mei: &str,
        right_mei: &str,
    ) -> ChannelInfo {
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
                hacash: right_mei.into(),
                satoshi: 0,
            },
            challenging: None,
        }
    }

    fn trusted_state(channel: &ChannelInfo) -> TrustedChannelState {
        TrustedChannelState {
            channel_id_hex: channel.id.clone(),
            reuse_version: channel.reuse_version,
            bill_auto_number: 0,
            left_address: channel.left.address.clone(),
            right_address: channel.right.address.clone(),
            left_balance: Amount::from(channel.left.hacash.as_str()).unwrap(),
            right_balance: Amount::from(channel.right.hacash.as_str()).unwrap(),
            left_satoshi: channel.left.satoshi,
            right_satoshi: channel.right.satoshi,
        }
    }

    #[test]
    fn summarize_signed_bill_marks_dispute_ready() {
        let alice = Account::create_by("alice-bill-summary").unwrap();
        let hub = Account::create_by("hub-bill-summary").unwrap();
        let channel_id = derive_channel_id(alice.readable(), hub.readable(), 1);
        let mut doc = build_same_channel_bill(
            &ChannelWireInput {
                channel: sample_channel(&channel_id, alice.readable(), hub.readable(), "5", "1"),
                channel_id_hex: channel_id,
                left_balance_mei: 4.0,
                right_balance_mei: 2.0,
                left_satoshi: 0,
                right_satoshi: 0,
                bill_auto_number: 1,
            },
            ChannelSide::Left,
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

    #[test]
    fn routed_bill_is_bound_to_sender_and_recipient_intent() {
        let alice = Account::create_by("alice-routed-binding").unwrap();
        let bob = Account::create_by("bob-routed-binding").unwrap();
        let carol = Account::create_by("carol-routed-binding").unwrap();
        let hub = Account::create_by("hub-routed-binding").unwrap();
        let payer_channel_id = derive_channel_id(alice.readable(), hub.readable(), 1);
        let payee_channel_id = derive_channel_id(bob.readable(), hub.readable(), 1);
        let payer_channel = sample_channel(
            &payer_channel_id,
            alice.readable(),
            hub.readable(),
            "10",
            "0",
        );
        let payee_channel =
            sample_channel(&payee_channel_id, bob.readable(), hub.readable(), "2", "5");
        let mut doc = build_cross_channel_bill(
            &ChannelWireInput {
                channel: payer_channel.clone(),
                channel_id_hex: payer_channel_id.clone(),
                left_balance_mei: 8.5,
                right_balance_mei: 1.5,
                left_satoshi: 0,
                right_satoshi: 0,
                bill_auto_number: 1,
            },
            ChannelSide::Left,
            1.5,
            &ChannelWireInput {
                channel: payee_channel.clone(),
                channel_id_hex: payee_channel_id.clone(),
                left_balance_mei: 3.5,
                right_balance_mei: 3.5,
                left_satoshi: 0,
                right_satoshi: 0,
                bill_auto_number: 1,
            },
            ChannelSide::Left,
            1.5,
            1_700_000_000,
        )
        .unwrap();
        doc.chain_payment.fill_sign_by_account(&hub).unwrap();
        let hub_signed = doc.to_bill_hex();
        let sender_trusted = trusted_state(&payer_channel);

        validate_sender_bill(
            "pay-routed",
            &hub_signed,
            alice.readable(),
            bob.readable(),
            "1.5",
            hub.readable(),
            &payer_channel_id,
            &sender_trusted,
        )
        .unwrap();
        assert!(
            validate_sender_bill(
                "pay-routed",
                &hub_signed,
                alice.readable(),
                bob.readable(),
                "1.4",
                hub.readable(),
                &payer_channel_id,
                &sender_trusted,
            )
            .is_err()
        );
        assert!(
            validate_sender_bill(
                "pay-routed",
                &hub_signed,
                alice.readable(),
                carol.readable(),
                "1.5",
                hub.readable(),
                &payer_channel_id,
                &sender_trusted,
            )
            .is_err()
        );

        doc.chain_payment.fill_sign_by_account(&alice).unwrap();
        let payer_signed = doc.to_bill_hex();
        let recipient_trusted = trusted_state(&payee_channel);
        validate_recipient_bill(
            "pay-routed",
            &payer_signed,
            alice.readable(),
            bob.readable(),
            "1.5",
            hub.readable(),
            &payer_channel_id,
            &payee_channel_id,
            &recipient_trusted,
        )
        .unwrap();
    }
}
