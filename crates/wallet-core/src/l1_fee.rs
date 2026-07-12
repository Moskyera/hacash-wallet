//! Dynamic L1 (classic ECDSA) fee estimation from node fee purity × tx wire size.

use crate::error::{WalletError, WalletResult};
use crate::hip23::{wire_mei_for_node, L1_DEFAULT_FEE_MEI};
use crate::node::{BuildTxResponse, NodeClient};
use crate::type4_fee::{
    fee_from_node_average, local_fee_from_wire_bytes, Type4FeeEstimate, L1_DEFAULT_LOWEST_FEE_PURITY,
};

pub type L1FeeEstimate = Type4FeeEstimate;

pub const L1_TX_TYPE: u8 = 1;
pub const L1_DEFAULT_WIRE_BYTES: usize = 166;
/// Probe fee used only to build unsigned tx body for size measurement.
pub const L1_PROBE_FEE_WIRE: &str = "1:244";

fn wire_bytes_from_build(built: &BuildTxResponse) -> WalletResult<usize> {
    let body = built
        .body
        .as_ref()
        .ok_or_else(|| WalletError::Transaction("missing tx body for fee estimate".into()))?;
    Ok((body.len() / 2).max(1))
}

pub fn fallback_l1_fee(wire_bytes: usize) -> L1FeeEstimate {
    L1FeeEstimate {
        fee_mei: L1_DEFAULT_FEE_MEI,
        fee_node: wire_mei_for_node(L1_PROBE_FEE_WIRE),
        fee_wire: L1_PROBE_FEE_WIRE.to_string(),
        wire_bytes,
        purity: L1_DEFAULT_LOWEST_FEE_PURITY,
    }
}

pub async fn estimate_l1_fee(node: &NodeClient, wire_bytes: usize) -> WalletResult<L1FeeEstimate> {
    let wire_bytes = wire_bytes.max(1);
    match node.query_fee_average(wire_bytes, L1_TX_TYPE).await {
        Ok(resp) => fee_from_node_average(&resp.feasible, wire_bytes, resp.purity),
        Err(_) => Ok(local_fee_from_wire_bytes(wire_bytes)),
    }
}

async fn estimate_from_build(
    node: &NodeClient,
    built: WalletResult<BuildTxResponse>,
    fallback_wire_bytes: usize,
) -> WalletResult<L1FeeEstimate> {
    let wire_bytes = match built {
        Ok(ref resp) if resp.ret == 0 => wire_bytes_from_build(resp).unwrap_or(fallback_wire_bytes),
        _ => fallback_wire_bytes,
    };
    estimate_l1_fee(node, wire_bytes)
        .await
        .or_else(|_| Ok(fallback_l1_fee(wire_bytes)))
}

pub async fn estimate_hac_l1_fee(
    node: &NodeClient,
    from: &str,
    to: &str,
    amount_wire: &str,
) -> WalletResult<L1FeeEstimate> {
    let probe = wire_mei_for_node(L1_PROBE_FEE_WIRE);
    let built = node.build_send_hac_tx(from, to, amount_wire, &probe).await;
    estimate_from_build(node, built, L1_DEFAULT_WIRE_BYTES).await
}

pub async fn estimate_hacd_l1_fee(
    node: &NodeClient,
    from: &str,
    to: &str,
    diamond_names: &[String],
) -> WalletResult<L1FeeEstimate> {
    let probe = wire_mei_for_node(L1_PROBE_FEE_WIRE);
    let built = node
        .build_send_diamond_tx(from, to, diamond_names, &probe)
        .await;
    let fallback = L1_DEFAULT_WIRE_BYTES.saturating_add(diamond_names.len().saturating_sub(1) * 24);
    estimate_from_build(node, built, fallback).await
}

pub async fn estimate_btc_l1_fee(
    node: &NodeClient,
    from: &str,
    to: &str,
    satoshi: u64,
) -> WalletResult<L1FeeEstimate> {
    let probe = wire_mei_for_node(L1_PROBE_FEE_WIRE);
    let built = node.build_send_btc_tx(from, to, satoshi, &probe).await;
    estimate_from_build(node, built, L1_DEFAULT_WIRE_BYTES).await
}

pub fn format_l1_fee_label(est: &L1FeeEstimate) -> String {
    format!("~{} HAC", est.fee_wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_matches_legacy_default() {
        let est = fallback_l1_fee(L1_DEFAULT_WIRE_BYTES);
        assert!((est.fee_mei - L1_DEFAULT_FEE_MEI).abs() < 1e-9);
        assert_eq!(est.fee_wire, L1_PROBE_FEE_WIRE);
    }
}