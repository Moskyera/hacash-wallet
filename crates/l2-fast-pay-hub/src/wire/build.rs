use field::{Address, Amount, ChannelId, Uint1, Uint4, Uint8};
use sha2::{Digest, Sha256};

use crate::amount::format_amount_mei;
use crate::error::{HubError, HubResult};
use crate::node::ChannelInfo;

use super::chain_payment::{clean_sort_addresses, OffChainChannelTransfer};
use super::documents::ChannelPayCompleteDocuments;
use super::prove_body::{TransferProveBody, DIRECTION_LEFT_TO_RIGHT, DIRECTION_RIGHT_TO_LEFT};
use super::satoshi_var::SatoshiVariation;

/// Channel parties + balances after hub ledger settlement.
#[derive(Debug, Clone)]
pub struct ChannelWireInput {
    pub channel: ChannelInfo,
    pub channel_id_hex: String,
    pub left_balance_mei: f64,
    pub right_balance_mei: f64,
    pub left_satoshi: u64,
    pub right_satoshi: u64,
    pub bill_auto_number: u64,
}

pub fn build_same_channel_bill(
    payer_channel: &ChannelWireInput,
    pay_amount_mei: f64,
    timestamp: u64,
) -> HubResult<ChannelPayCompleteDocuments> {
    let body = prove_body_after_transfer(
        payer_channel,
        pay_amount_mei,
        customer_pays_from_left(payer_channel)?,
    )?;
    let addrs = clean_sort_addresses(vec![
        address_for_wire(&payer_channel.channel.left.address)?,
        address_for_wire(&payer_channel.channel.right.address)?,
    ]);
    let chain_payment =
        OffChainChannelTransfer::from_prove_bodies(std::slice::from_ref(&body), addrs, timestamp);
    Ok(ChannelPayCompleteDocuments {
        prove_bodies: vec![body],
        chain_payment,
    })
}

pub fn build_cross_channel_bill(
    payer_channel: &ChannelWireInput,
    pay_total_mei: f64,
    payee_channel: &ChannelWireInput,
    credit_amount_mei: f64,
    timestamp: u64,
) -> HubResult<ChannelPayCompleteDocuments> {
    let pay_body = prove_body_after_transfer(
        payer_channel,
        pay_total_mei,
        customer_pays_from_left(payer_channel)?,
    )?;
    let collect_body = prove_body_after_transfer(
        payee_channel,
        credit_amount_mei,
        customer_collects_on_left(payee_channel)?,
    )?;
    let addrs = clean_sort_addresses(vec![
        address_for_wire(&payer_channel.channel.left.address)?,
        address_for_wire(&payer_channel.channel.right.address)?,
        address_for_wire(&payee_channel.channel.left.address)?,
        address_for_wire(&payee_channel.channel.right.address)?,
    ]);
    let chain_payment = OffChainChannelTransfer::from_prove_bodies(
        &[pay_body.clone(), collect_body.clone()],
        addrs,
        timestamp,
    );
    Ok(ChannelPayCompleteDocuments {
        prove_bodies: vec![pay_body, collect_body],
        chain_payment,
    })
}

fn customer_pays_from_left(_input: &ChannelWireInput) -> HubResult<TransferSide> {
    // Wallet opens channel as user=left, hub=right.
    Ok(TransferSide {
        customer_is_left: true,
        direction: DIRECTION_LEFT_TO_RIGHT,
    })
}

fn customer_collects_on_left(_input: &ChannelWireInput) -> HubResult<TransferSide> {
    Ok(TransferSide {
        customer_is_left: true,
        direction: DIRECTION_RIGHT_TO_LEFT,
    })
}

struct TransferSide {
    customer_is_left: bool,
    direction: u8,
}

fn prove_body_after_transfer(
    input: &ChannelWireInput,
    pay_amount_mei: f64,
    side: TransferSide,
) -> HubResult<TransferProveBody> {
    let _ = side.customer_is_left;
    Ok(TransferProveBody {
        channel_id: channel_id_from_hex(&input.channel_id_hex)?,
        reuse_version: Uint4::from(input.channel.reuse_version as u32),
        bill_auto_number: Uint8::from(input.bill_auto_number.min(255)),
        pay_direction: Uint1::from(side.direction),
        pay_amount: amount_from_mei(pay_amount_mei)?,
        pay_satoshi: SatoshiVariation::empty(),
        left_balance: amount_from_mei(input.left_balance_mei)?,
        right_balance: amount_from_mei(input.right_balance_mei)?,
        left_satoshi: SatoshiVariation::from_sat(input.left_satoshi),
        right_satoshi: SatoshiVariation::from_sat(input.right_satoshi),
        left_address: address_for_wire(&input.channel.left.address)?,
        right_address: address_for_wire(&input.channel.right.address)?,
    })
}

fn amount_from_mei(mei: f64) -> HubResult<Amount> {
    Amount::from(&format_amount_mei(mei)).map_err(|e| HubError::Payment(e.to_string()))
}

/// Map node readable address to wire `Address` (base58check, or deterministic dev fallback).
pub fn address_for_wire(readable: &str) -> HubResult<Address> {
    if let Ok(addr) = Address::from_readable(readable) {
        return Ok(addr);
    }
    let mut data = [0u8; 21];
    data[0] = Address::PRIVAKEY;
    let hash = Sha256::digest(readable.as_bytes());
    data[1..].copy_from_slice(&hash[..20]);
    Ok(Address::from(data))
}

fn channel_id_from_hex(hex32: &str) -> HubResult<ChannelId> {
    let bytes = hex::decode(hex32).map_err(|e| HubError::Channel(e.to_string()))?;
    if bytes.len() != 16 {
        return Err(HubError::Channel(format!(
            "channel id must be 32 hex chars, got {}",
            hex32.len()
        )));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(ChannelId::from(arr))
}