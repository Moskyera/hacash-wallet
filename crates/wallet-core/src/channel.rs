use basis::interface::Transaction;
use field::{
    AddrHac, AddrOrPtr, Address, Amount, ChannelId, Field, Serialize as FieldSerialize, Uint4,
};
use mint::action::{ChannelClose, ChannelOpen};
use protocol::action::{ChainAllow, ChainIDList, HacFromToTrs};
use protocol::transaction::TransactionType2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};
use crate::l1_fee::{estimate_l1_fee_for_type, signed_l1_wire_bytes_for_signatures};
use crate::node::{BuildTxResponse, NodeClient};
use crate::send_options::L1FeeSpeed;

pub const CHANNEL_STATUS_OPENING: u8 = 0;
pub const CHANNEL_STATUS_AGREEMENT_CLOSED: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelPartyBalance {
    pub address: String,
    pub hacash: String,
    pub satoshi: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ChannelChallenging {
    #[serde(default)]
    pub assert_bill_auto_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelInfo {
    #[serde(default)]
    pub ret: i32,
    pub id: String,
    pub status: u8,
    pub open_height: u64,
    pub close_height: u64,
    pub reuse_version: u64,
    pub arbitration_lock: u64,
    pub left: ChannelPartyBalance,
    pub right: ChannelPartyBalance,
    #[serde(default)]
    pub challenging: Option<ChannelChallenging>,
}

impl ChannelInfo {
    pub fn is_open(&self) -> bool {
        self.status == CHANNEL_STATUS_OPENING
    }

    pub fn user_is_left(&self, user_address: &str) -> bool {
        self.left.address == user_address
    }

    pub fn user_is_right(&self, user_address: &str) -> bool {
        self.right.address == user_address
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CooperativeCloseTransfer {
    pub from_address: String,
    pub to_address: String,
    pub amount_millimeis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CooperativeCloseSettlement {
    pub channel_id: String,
    pub reuse_version: u64,
    pub bill_auto_number: u64,
    pub left_address: String,
    pub right_address: String,
    pub original_left_millimeis: u64,
    pub original_right_millimeis: u64,
    pub final_left_millimeis: u64,
    pub final_right_millimeis: u64,
    pub transfer: Option<CooperativeCloseTransfer>,
}

/// Opaque, exact cooperative-close plan produced from the live channel and the
/// latest fully signed bill in the caller-selected BillStore. Callers may
/// display and commit these fields, but cannot invent a settlement independently
/// of wallet-core's conservation and channel-incarnation checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedCooperativeChannelClose {
    pub channel_id: String,
    pub reuse_version: u64,
    pub open_height: u64,
    pub bill_auto_number: u64,
    pub left_address: String,
    pub right_address: String,
    pub original_left_millimeis: u64,
    pub original_right_millimeis: u64,
    pub final_left_millimeis: u64,
    pub final_right_millimeis: u64,
    pub transfer_from: Option<String>,
    pub transfer_to: Option<String>,
    pub transfer_millimeis: Option<u64>,
    pub unsigned_transaction_hex: String,
    pub network_fee: String,
}

impl PreparedCooperativeChannelClose {
    pub fn requires_principal_transfer(&self) -> bool {
        self.transfer_millimeis.is_some()
    }

    pub fn exact_actions(&self, chain_id: u32) -> WalletResult<Vec<serde_json::Value>> {
        let mut actions = vec![
            serde_json::json!({ "kind": 0x0411, "chains": [chain_id] }),
            serde_json::json!({
                "kind": 3,
                "channel_id": encoded_channel_id(&self.channel_id)?,
            }),
        ];
        match (
            self.transfer_from.as_deref(),
            self.transfer_to.as_deref(),
            self.transfer_millimeis,
        ) {
            (None, None, None) => {}
            (Some(from), Some(to), Some(amount)) if amount > 0 => {
                actions.push(serde_json::json!({
                    "kind": 14,
                    "from": from,
                    "to": to,
                    "hacash": format_millimeis_hac(amount),
                }));
            }
            _ => {
                return Err(WalletError::Policy(
                    "cooperative close transfer evidence is incomplete".into(),
                ));
            }
        }
        Ok(actions)
    }
}

/// Prepare one exact cooperative close without signing. The BillStore path is
/// chosen by the caller, which lets Personal and Agent wallets share the
/// protocol logic without sharing settlement history.
pub async fn prepare_cooperative_channel_close(
    node: &NodeClient,
    chain_id: u32,
    fee_payer: &str,
    channel: &ChannelInfo,
    bills: &crate::bills::BillStore,
    speed: L1FeeSpeed,
) -> WalletResult<PreparedCooperativeChannelClose> {
    if !channel.is_open()
        || channel.close_height != 0
        || channel.open_height == 0
        || channel.reuse_version == 0
        || channel.challenging.is_some()
        || !channel.user_is_left(fee_payer)
    {
        return Err(WalletError::Policy(
            "channel is not the exact unchallenged Agent-left open incarnation".into(),
        ));
    }
    let trusted = crate::l2_bill::trusted_channel_state(bills, channel)?;
    let settlement = cooperative_close_settlement(channel, &trusted)?;
    let (built, network_fee) = build_channel_close_tx_with_dynamic_fee(
        node,
        chain_id,
        fee_payer,
        &channel.id,
        &settlement,
        speed,
    )
    .await?;
    let unsigned_transaction_hex = built
        .body
        .ok_or_else(|| WalletError::Transaction("missing channel close body".into()))?;
    let (transfer_from, transfer_to, transfer_millimeis) = settlement
        .transfer
        .as_ref()
        .map(|transfer| {
            (
                Some(transfer.from_address.clone()),
                Some(transfer.to_address.clone()),
                Some(transfer.amount_millimeis),
            )
        })
        .unwrap_or((None, None, None));
    let plan = PreparedCooperativeChannelClose {
        channel_id: settlement.channel_id,
        reuse_version: settlement.reuse_version,
        open_height: channel.open_height,
        bill_auto_number: settlement.bill_auto_number,
        left_address: settlement.left_address,
        right_address: settlement.right_address,
        original_left_millimeis: settlement.original_left_millimeis,
        original_right_millimeis: settlement.original_right_millimeis,
        final_left_millimeis: settlement.final_left_millimeis,
        final_right_millimeis: settlement.final_right_millimeis,
        transfer_from,
        transfer_to,
        transfer_millimeis,
        unsigned_transaction_hex,
        network_fee,
    };
    crate::tx_binding::verify_transaction_intent(
        &plan.unsigned_transaction_hex,
        fee_payer,
        &plan.network_fee,
        &plan.exact_actions(chain_id)?,
    )?;
    Ok(plan)
}

/// Revalidate a previously reviewed close plan against the current channel and
/// latest authenticated bill without rebuilding it or changing its reviewed
/// network fee.
pub fn validate_cooperative_channel_close_plan(
    chain_id: u32,
    fee_payer: &str,
    channel: &ChannelInfo,
    bills: &crate::bills::BillStore,
    plan: &PreparedCooperativeChannelClose,
) -> WalletResult<()> {
    if !channel.is_open()
        || channel.close_height != 0
        || channel.open_height != plan.open_height
        || channel.reuse_version != plan.reuse_version
        || channel.challenging.is_some()
        || channel.id != plan.channel_id
        || !channel.user_is_left(fee_payer)
    {
        return Err(WalletError::Policy(
            "live channel changed after cooperative close review".into(),
        ));
    }
    let trusted = crate::l2_bill::trusted_channel_state(bills, channel)?;
    let settlement = cooperative_close_settlement(channel, &trusted)?;
    let exact = settlement.channel_id == plan.channel_id
        && settlement.reuse_version == plan.reuse_version
        && settlement.bill_auto_number == plan.bill_auto_number
        && settlement.left_address == plan.left_address
        && settlement.right_address == plan.right_address
        && settlement.original_left_millimeis == plan.original_left_millimeis
        && settlement.original_right_millimeis == plan.original_right_millimeis
        && settlement.final_left_millimeis == plan.final_left_millimeis
        && settlement.final_right_millimeis == plan.final_right_millimeis
        && settlement
            .transfer
            .as_ref()
            .map(|value| value.from_address.as_str())
            == plan.transfer_from.as_deref()
        && settlement
            .transfer
            .as_ref()
            .map(|value| value.to_address.as_str())
            == plan.transfer_to.as_deref()
        && settlement
            .transfer
            .as_ref()
            .map(|value| value.amount_millimeis)
            == plan.transfer_millimeis;
    if !exact {
        return Err(WalletError::Policy(
            "latest signed Fast Pay bill changed after cooperative close review".into(),
        ));
    }
    crate::tx_binding::verify_transaction_intent(
        &plan.unsigned_transaction_hex,
        fee_payer,
        &plan.network_fee,
        &plan.exact_actions(chain_id)?,
    )?;
    Ok(())
}

pub(crate) fn cooperative_close_settlement(
    channel: &ChannelInfo,
    trusted: &crate::l2_bill::TrustedChannelState,
) -> WalletResult<CooperativeCloseSettlement> {
    if !channel.id.eq_ignore_ascii_case(&trusted.channel_id_hex)
        || channel.reuse_version != trusted.reuse_version
        || channel.left.address != trusted.left_address
        || channel.right.address != trusted.right_address
    {
        return Err(WalletError::Policy(
            "latest signed bill does not match the exact open channel incarnation".into(),
        ));
    }
    if channel.left.satoshi != 0
        || channel.right.satoshi != 0
        || trusted.left_satoshi != 0
        || trusted.right_satoshi != 0
    {
        return Err(WalletError::Policy(
            "cooperative Fast Pay close currently supports HAC-only channels".into(),
        ));
    }
    let original_left_millimeis = exact_millimeis(
        &parse_amount(&channel.left.hacash, "on-chain left channel balance")?,
        "on-chain left channel balance",
    )?;
    let original_right_millimeis = exact_millimeis(
        &parse_amount(&channel.right.hacash, "on-chain right channel balance")?,
        "on-chain right channel balance",
    )?;
    let final_left_millimeis = exact_millimeis(&trusted.left_balance, "signed left balance")?;
    let final_right_millimeis = exact_millimeis(&trusted.right_balance, "signed right balance")?;
    let original_total = original_left_millimeis
        .checked_add(original_right_millimeis)
        .ok_or_else(|| WalletError::Policy("original channel balance overflow".into()))?;
    let final_total = final_left_millimeis
        .checked_add(final_right_millimeis)
        .ok_or_else(|| WalletError::Policy("final channel balance overflow".into()))?;
    if original_total != final_total {
        return Err(WalletError::Policy(
            "latest signed bill does not conserve the original channel principal".into(),
        ));
    }
    let transfer = if final_left_millimeis < original_left_millimeis {
        Some(CooperativeCloseTransfer {
            from_address: channel.left.address.clone(),
            to_address: channel.right.address.clone(),
            amount_millimeis: original_left_millimeis - final_left_millimeis,
        })
    } else if final_left_millimeis > original_left_millimeis {
        Some(CooperativeCloseTransfer {
            from_address: channel.right.address.clone(),
            to_address: channel.left.address.clone(),
            amount_millimeis: final_left_millimeis - original_left_millimeis,
        })
    } else {
        None
    };
    Ok(CooperativeCloseSettlement {
        channel_id: channel.id.to_ascii_lowercase(),
        reuse_version: channel.reuse_version,
        bill_auto_number: trusted.bill_auto_number,
        left_address: channel.left.address.clone(),
        right_address: channel.right.address.clone(),
        original_left_millimeis,
        original_right_millimeis,
        final_left_millimeis,
        final_right_millimeis,
        transfer,
    })
}

pub fn derive_channel_id(left: &str, right: &str, reuse_version: u64) -> String {
    let seed = format!("{left}|{right}|{reuse_version}");
    let hash = Sha256::digest(seed.as_bytes());
    hex::encode(&hash[..16])
}

pub async fn query_channel(node: &NodeClient, channel_id_hex: &str) -> WalletResult<ChannelInfo> {
    let url = format!(
        "{}/query/channel?unit=mei&id={}",
        node.base_url(),
        channel_id_hex
    );
    let resp = node
        .http()
        .get(url)
        .send()
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    // Read the node's own verdict before demanding the full channel shape. A
    // real Hacash fullnode answers an unknown channel with
    // `{"err":"channel not found","ret":1}` and nothing else, which does not
    // deserialize into `ChannelInfo`; decoding first turned every
    // never-opened channel into an opaque "error decoding response body" and
    // made the `channel not found` branch every caller depends on
    // unreachable. The Hub's own client already reads it in this order
    // (`l2-fast-pay-hub/src/node.rs`), and the Hub is the half that was
    // proven against the live chain.
    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| WalletError::Node(e.to_string()))?;
    if value.get("ret").and_then(serde_json::Value::as_i64) != Some(0) {
        let message = value
            .get("err")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("fullnode rejected the channel query")
            .trim();
        if message.eq_ignore_ascii_case("channel not found") {
            return Err(WalletError::Node("channel not found".into()));
        }
        // Anything else is not "there is no channel here". Saying so would
        // invite a caller to open a second incarnation over a channel the
        // node simply would not talk about.
        return Err(WalletError::Node(format!(
            "fullnode channel query rejected: {message}"
        )));
    }
    let info: ChannelInfo = serde_json::from_value(value)
        .map_err(|e| WalletError::Node(format!("invalid fullnode channel response: {e}")))?;
    Ok(info)
}

/// Return the exact Hacash reuse version that a new incarnation must use.
///
/// Hacash reuses the same channel ID only after an agreement close and only
/// for the same ordered parties. Any other existing state fails closed.
pub async fn next_channel_reuse_version(
    node: &NodeClient,
    channel_id_hex: &str,
    left_address: &str,
    right_address: &str,
) -> WalletResult<u64> {
    match query_channel(node, channel_id_hex).await {
        Ok(existing) => {
            if existing.status != CHANNEL_STATUS_AGREEMENT_CLOSED
                || existing.close_height == 0
                || existing.challenging.is_some()
                || existing.left.address != left_address
                || existing.right.address != right_address
                || existing.left.satoshi != 0
                || existing.right.satoshi != 0
            {
                return Err(WalletError::L2(
                    "existing channel is not the exact reusable agreement-closed incarnation"
                        .into(),
                ));
            }
            existing
                .reuse_version
                .checked_add(1)
                .ok_or_else(|| WalletError::L2("channel reuse version overflow".into()))
        }
        Err(WalletError::Node(message)) if message.contains("channel not found") => Ok(1),
        Err(error) => Err(error),
    }
}

// The arguments map one-to-one to the protocol's channel-open action fields.
#[allow(clippy::too_many_arguments)]
pub async fn build_channel_open_tx(
    node: &NodeClient,
    chain_id: u32,
    fee_payer: &str,
    channel_id_hex: &str,
    left_address: &str,
    left_amount: &str,
    right_address: &str,
    right_amount: &str,
    fee: &str,
) -> WalletResult<BuildTxResponse> {
    let _ = node;
    let mut tx = TransactionType2::new_by(
        parse_address(fee_payer, "channel fee payer")?,
        parse_amount(fee, "channel fee")?,
        sys::curtimes(),
    );
    let mut chain_guard = ChainAllow::new();
    chain_guard.chains = ChainIDList::from_list(vec![Uint4::from(chain_id)])
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    tx.push_action(Box::new(chain_guard))
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let mut action = ChannelOpen::new();
    action.channel_id = parse_channel_id(channel_id_hex)?;
    action.left_bill = AddrHac {
        address: parse_address(left_address, "left channel address")?,
        amount: parse_amount(left_amount, "left channel amount")?,
    };
    action.right_bill = AddrHac {
        address: parse_address(right_address, "right channel address")?,
        amount: parse_amount(right_amount, "right channel amount")?,
    };
    tx.push_action(Box::new(action))
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    Ok(local_build_response(hex::encode(tx.serialize())))
}

/// Build once to measure signed size, then rebuild with the current node-derived fee.
#[allow(clippy::too_many_arguments)]
pub async fn build_channel_open_tx_with_dynamic_fee(
    node: &NodeClient,
    chain_id: u32,
    fee_payer: &str,
    channel_id_hex: &str,
    left_address: &str,
    left_amount: &str,
    right_address: &str,
    right_amount: &str,
    speed: L1FeeSpeed,
) -> WalletResult<(BuildTxResponse, String)> {
    let probe_fee = crate::hip23::format_l1_fee_mei_for_node(crate::hip23::L1_DEFAULT_FEE_MEI);
    let probe = build_channel_open_tx(
        node,
        chain_id,
        fee_payer,
        channel_id_hex,
        left_address,
        left_amount,
        right_address,
        right_amount,
        &probe_fee,
    )
    .await?;
    let body = probe.body.as_ref().ok_or_else(|| {
        WalletError::Transaction("missing channel open body for fee estimate".into())
    })?;
    let fee = estimate_l1_fee_for_type(
        node,
        signed_l1_wire_bytes_for_signatures((body.len() / 2).max(1), 2),
        speed,
        2,
    )
    .await?;
    let built = build_channel_open_tx(
        node,
        chain_id,
        fee_payer,
        channel_id_hex,
        left_address,
        left_amount,
        right_address,
        right_amount,
        &fee.fee_node,
    )
    .await?;
    Ok((built, fee.fee_node))
}

pub async fn build_channel_close_tx(
    node: &NodeClient,
    chain_id: u32,
    fee_payer: &str,
    channel_id_hex: &str,
    fee: &str,
) -> WalletResult<BuildTxResponse> {
    build_channel_close_tx_for_settlement(node, chain_id, fee_payer, channel_id_hex, None, fee)
        .await
}

async fn build_channel_close_tx_for_settlement(
    node: &NodeClient,
    chain_id: u32,
    fee_payer: &str,
    channel_id_hex: &str,
    transfer: Option<&CooperativeCloseTransfer>,
    fee: &str,
) -> WalletResult<BuildTxResponse> {
    let _ = node;
    let mut tx = TransactionType2::new_by(
        parse_address(fee_payer, "channel fee payer")?,
        parse_amount(fee, "channel fee")?,
        sys::curtimes(),
    );
    let mut chain_guard = ChainAllow::new();
    chain_guard.chains = ChainIDList::from_list(vec![Uint4::from(chain_id)])
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    tx.push_action(Box::new(chain_guard))
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    let mut action = ChannelClose::new();
    action.channel_id = parse_channel_id(channel_id_hex)?;
    tx.push_action(Box::new(action))
        .map_err(|error| WalletError::Transaction(error.to_string()))?;
    if let Some(transfer) = transfer {
        if transfer.amount_millimeis == 0 {
            return Err(WalletError::Policy(
                "cooperative close principal transfer must be positive".into(),
            ));
        }
        let mut action = HacFromToTrs::new();
        action.from = AddrOrPtr::from_addr(parse_address(
            &transfer.from_address,
            "close principal sender",
        )?);
        action.to = AddrOrPtr::from_addr(parse_address(
            &transfer.to_address,
            "close principal recipient",
        )?);
        action.hacash = parse_amount(
            &format_millimeis_hac(transfer.amount_millimeis),
            "close principal amount",
        )?;
        tx.push_action(Box::new(action))
            .map_err(|error| WalletError::Transaction(error.to_string()))?;
    }
    Ok(local_build_response(hex::encode(tx.serialize())))
}

pub(crate) async fn build_channel_close_tx_with_dynamic_fee(
    node: &NodeClient,
    chain_id: u32,
    fee_payer: &str,
    channel_id_hex: &str,
    settlement: &CooperativeCloseSettlement,
    speed: L1FeeSpeed,
) -> WalletResult<(BuildTxResponse, String)> {
    let probe_fee = crate::hip23::format_l1_fee_mei_for_node(crate::hip23::L1_DEFAULT_FEE_MEI);
    let probe = build_channel_close_tx_for_settlement(
        node,
        chain_id,
        fee_payer,
        channel_id_hex,
        settlement.transfer.as_ref(),
        &probe_fee,
    )
    .await?;
    let body = probe.body.as_ref().ok_or_else(|| {
        WalletError::Transaction("missing channel close body for fee estimate".into())
    })?;
    let fee = estimate_l1_fee_for_type(
        node,
        signed_l1_wire_bytes_for_signatures((body.len() / 2).max(1), 2),
        speed,
        2,
    )
    .await?;
    let built = build_channel_close_tx_for_settlement(
        node,
        chain_id,
        fee_payer,
        channel_id_hex,
        settlement.transfer.as_ref(),
        &fee.fee_node,
    )
    .await?;
    Ok((built, fee.fee_node))
}

fn parse_address(value: &str, label: &str) -> WalletResult<Address> {
    Address::from_readable(value)
        .map_err(|error| WalletError::Transaction(format!("invalid {label}: {error}")))
}

fn parse_amount(value: &str, label: &str) -> WalletResult<Amount> {
    Amount::from(value)
        .map_err(|error| WalletError::Transaction(format!("invalid {label}: {error}")))
}

fn exact_millimeis(amount: &Amount, label: &str) -> WalletResult<u64> {
    if amount.is_negative() {
        return Err(WalletError::Policy(format!("{label} cannot be negative")));
    }
    let zhu = amount
        .to_zhu_u64()
        .map_err(|error| WalletError::Policy(format!("invalid {label}: {error}")))?;
    if zhu % l2_fast_pay_hub::readiness::ZHU_PER_MILLIMEI != 0 {
        return Err(WalletError::Policy(format!(
            "{label} must use exact millimei precision"
        )));
    }
    Ok(zhu / l2_fast_pay_hub::readiness::ZHU_PER_MILLIMEI)
}

pub(crate) fn format_millimeis_hac(millimeis: u64) -> String {
    let whole = millimeis / 1_000;
    let fractional = millimeis % 1_000;
    if fractional == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{fractional:03}")
            .trim_end_matches('0')
            .to_string()
    }
}

fn parse_channel_id(channel_id_hex: &str) -> WalletResult<ChannelId> {
    let clean = channel_id_hex
        .trim()
        .strip_prefix("0x")
        .unwrap_or(channel_id_hex.trim());
    let raw = hex::decode(clean).map_err(|_| {
        WalletError::Transaction("channel id must be 32 hexadecimal characters".into())
    })?;
    let bytes: [u8; 16] = raw
        .try_into()
        .map_err(|_| WalletError::Transaction("channel id must encode exactly 16 bytes".into()))?;
    Ok(ChannelId::from(bytes))
}

fn local_build_response(body: String) -> BuildTxResponse {
    BuildTxResponse {
        ret: 0,
        err: None,
        error: None,
        message: None,
        code: None,
        stage: None,
        body: Some(body),
        hash: None,
        details: serde_json::Map::new(),
    }
}

pub fn encoded_channel_id(channel_id_hex: &str) -> WalletResult<String> {
    Ok(format!("0x{}", parse_channel_id(channel_id_hex)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_binding::decode_transaction;

    const LEFT_ADDRESS: &str = "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS";
    const RIGHT_ADDRESS: &str = "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW";
    const CHANNEL_ID: &str = "00112233445566778899aabbccddeeff";

    fn open_channel() -> ChannelInfo {
        ChannelInfo {
            ret: 0,
            id: CHANNEL_ID.into(),
            status: CHANNEL_STATUS_OPENING,
            open_height: 765_500,
            close_height: 0,
            reuse_version: 1,
            arbitration_lock: 0,
            left: ChannelPartyBalance {
                address: LEFT_ADDRESS.into(),
                hacash: "0.01".into(),
                satoshi: 0,
            },
            right: ChannelPartyBalance {
                address: RIGHT_ADDRESS.into(),
                hacash: "0".into(),
                satoshi: 0,
            },
            challenging: None,
        }
    }

    fn trusted_state(left: &str, right: &str) -> crate::l2_bill::TrustedChannelState {
        crate::l2_bill::TrustedChannelState {
            channel_id_hex: CHANNEL_ID.into(),
            reuse_version: 1,
            bill_auto_number: 7,
            left_address: LEFT_ADDRESS.into(),
            right_address: RIGHT_ADDRESS.into(),
            left_balance: Amount::from(left).unwrap(),
            right_balance: Amount::from(right).unwrap(),
            left_satoshi: 0,
            right_satoshi: 0,
        }
    }

    #[test]
    fn channel_id_is_deterministic_32_hex() {
        let id = derive_channel_id("1Left", "1Right", 1);
        assert_eq!(id.len(), 32);
        assert_eq!(id, derive_channel_id("1Left", "1Right", 1));
    }

    #[test]
    fn channel_id_is_encoded_for_fixed16_json() {
        assert_eq!(
            encoded_channel_id(CHANNEL_ID).unwrap(),
            "0x00112233445566778899aabbccddeeff"
        );
        assert!(encoded_channel_id("0011").is_err());
    }

    #[tokio::test]
    async fn local_channel_open_keeps_zero_hub_deposit_and_requires_both_signers() {
        let node = NodeClient::new("http://127.0.0.1:1").unwrap();
        let built = build_channel_open_tx(
            &node,
            7,
            LEFT_ADDRESS,
            CHANNEL_ID,
            LEFT_ADDRESS,
            "0.01",
            RIGHT_ADDRESS,
            "0",
            "0.0001",
        )
        .await
        .unwrap();
        let canonical = decode_transaction(built.body.as_deref().unwrap()).unwrap();

        assert_eq!(canonical.tx_type, 2);
        assert_eq!(canonical.main_address, LEFT_ADDRESS);
        assert_eq!(canonical.fee, "1:244");
        assert_eq!(canonical.actions.len(), 2);
        assert_eq!(canonical.actions[0].kind, 0x0411);
        assert_eq!(canonical.actions[1].kind, 2);
        assert_eq!(
            canonical.actions[1]
                .canonical_json
                .pointer("/right_bill/amount")
                .and_then(serde_json::Value::as_str),
            Some("0:0")
        );
        let mut expected = vec![LEFT_ADDRESS.to_string(), RIGHT_ADDRESS.to_string()];
        expected.sort();
        assert_eq!(canonical.required_signers, expected);
    }

    #[tokio::test]
    async fn local_channel_close_is_type2_and_requires_channel_parties_at_execution() {
        let node = NodeClient::new("http://127.0.0.1:1").unwrap();
        let built = build_channel_close_tx(&node, 7, LEFT_ADDRESS, CHANNEL_ID, "0.0001")
            .await
            .unwrap();
        let canonical = decode_transaction(built.body.as_deref().unwrap()).unwrap();

        assert_eq!(canonical.tx_type, 2);
        assert_eq!(canonical.main_address, LEFT_ADDRESS);
        assert_eq!(canonical.fee, "1:244");
        assert_eq!(canonical.actions.len(), 2);
        assert_eq!(canonical.actions[0].kind, 0x0411);
        assert_eq!(canonical.actions[1].kind, 3);
        assert_eq!(canonical.required_signers, vec![LEFT_ADDRESS.to_string()]);
        // ChannelClose obtains the counterparty requirement dynamically from on-chain channel
        // state. The Hub co-sign adapter must therefore query and bind both channel parties.
    }

    #[tokio::test]
    async fn cooperative_close_encodes_the_exact_signed_bill_delta() {
        let channel = open_channel();
        let settlement =
            cooperative_close_settlement(&channel, &trusted_state("0.009", "0.001")).unwrap();
        assert_eq!(
            settlement.transfer,
            Some(CooperativeCloseTransfer {
                from_address: LEFT_ADDRESS.into(),
                to_address: RIGHT_ADDRESS.into(),
                amount_millimeis: 1,
            })
        );
        let node = NodeClient::new("http://127.0.0.1:1").unwrap();
        let built = build_channel_close_tx_for_settlement(
            &node,
            7,
            LEFT_ADDRESS,
            CHANNEL_ID,
            settlement.transfer.as_ref(),
            "0.0001",
        )
        .await
        .unwrap();
        let canonical = decode_transaction(built.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            canonical
                .actions
                .iter()
                .map(|action| action.kind)
                .collect::<Vec<_>>(),
            vec![0x0411, 3, 14]
        );
        assert_eq!(
            canonical.actions[2]
                .canonical_json
                .get("hacash")
                .and_then(serde_json::Value::as_str),
            Some("1:245")
        );
    }

    #[test]
    fn cooperative_close_rejects_non_conserving_or_sub_millimei_state() {
        let channel = open_channel();
        assert!(cooperative_close_settlement(&channel, &trusted_state("0.009", "0")).is_err());
        assert!(
            cooperative_close_settlement(&channel, &trusted_state("0.0099", "0.0001")).is_err()
        );
    }

    /// The exact bytes a real Hacash fullnode serves for a channel that does
    /// not exist, and for one that does.
    ///
    /// Captured with `curl` from `hacash-fullnode 1.0.10` on private chain 7:
    ///
    /// ```text
    /// $ curl 'http://127.0.0.1:8217/query/channel?unit=mei&id=00112233445566778899aabbccddeeff'
    /// {"err":"channel not found","ret":1}
    /// ```
    ///
    /// That body carries no `id`, `status`, `left` or `right`, so decoding it
    /// into `ChannelInfo` first fails, and the failure used to surface as
    /// `error decoding response body` rather than `channel not found`. Every
    /// caller that opens a first channel branches on the latter, so the very
    /// first channel open against a live node could not get past the preview.
    /// The mocked node in the Hub's own tests answers with a fully populated
    /// object carrying `ret: 1`, which is why nothing caught it.
    #[tokio::test]
    async fn a_missing_channel_reads_as_not_found_on_the_real_wire_shape() {
        use axum::{Router, routing::get};

        let app = Router::new()
            .route(
                "/query/channel",
                get(|axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    match query.get("id").map(String::as_str) {
                        Some("00112233445566778899aabbccddeeff") => {
                            r#"{"err":"channel not found","ret":1}"#
                        }
                        Some("aabb00112233445566778899ccddeeff") => {
                            r#"{"err":"fullnode is still syncing","ret":1}"#
                        }
                        _ => {
                            r#"{"arbitration_lock":5000,"close_height":0,"id":"2ff63939188c96bb6b1ace32ab88faac","interest_attribution":0,"left":{"address":"1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS","hacash":"1","satoshi":0},"open_height":42,"ret":0,"reuse_version":1,"right":{"address":"1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW","hacash":"0","satoshi":0},"status":0}"#
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let node = NodeClient::new(base).unwrap();

        let missing = query_channel(&node, CHANNEL_ID).await.unwrap_err();
        assert!(
            missing.to_string().contains("channel not found"),
            "{missing}"
        );
        assert_eq!(
            next_channel_reuse_version(&node, CHANNEL_ID, LEFT_ADDRESS, RIGHT_ADDRESS)
                .await
                .unwrap(),
            1,
            "a channel the node has never seen is incarnation 1"
        );

        // A node that refuses to answer is not a node saying there is no
        // channel. It must not read as an invitation to open one.
        let refused = query_channel(&node, "aabb00112233445566778899ccddeeff")
            .await
            .unwrap_err();
        assert!(refused.to_string().contains("still syncing"), "{refused}");
        assert!(!refused.to_string().contains("channel not found"));
        assert!(
            next_channel_reuse_version(
                &node,
                "aabb00112233445566778899ccddeeff",
                LEFT_ADDRESS,
                RIGHT_ADDRESS
            )
            .await
            .is_err()
        );

        // And a real channel still has to decode in full.
        let live = query_channel(&node, "2ff63939188c96bb6b1ace32ab88faac")
            .await
            .unwrap();
        assert_eq!(live.status, CHANNEL_STATUS_OPENING);
        assert_eq!(live.reuse_version, 1);
        assert_eq!(live.left.hacash, "1");

        server.abort();
    }
}
