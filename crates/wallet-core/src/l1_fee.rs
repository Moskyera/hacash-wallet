//! Dynamic L1 (classic ECDSA) fee estimation from node fee purity × tx wire size.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::hip23::{L1_DEFAULT_FEE_MEI, format_l1_fee_mei_for_node, wire_mei_for_node};
use crate::node::{BuildTxResponse, NodeClient};
use crate::send_options::{
    HACD_SERVICE_FEE_MEI, L1FeeSpeed, WALLET_TREASURY_ADDRESS, compute_btc_service_fee_satoshi,
    compute_service_fee_mei, format_service_fee_amount_wire,
};
use crate::type4_fee::{
    L1_DEFAULT_LOWEST_FEE_PURITY, Type4FeeEstimate, local_fee_from_wire_bytes, mei_to_fee_wire,
    parse_fee_mei_decimal,
};

pub type L1FeeEstimate = Type4FeeEstimate;

pub const L1_TX_TYPE: u8 = 1;
pub const L1_DEFAULT_WIRE_BYTES: usize = 166;
/// One legacy secp256k1 signature contains a 33-byte public key and a
/// 64-byte signature. Node build responses are unsigned, while fee purity is
/// checked against the signed transaction size.
pub const L1_LEGACY_SIGNATURE_BYTES: usize = 97;
/// Probe fee used only to build unsigned tx body for size measurement.
pub const L1_PROBE_FEE_WIRE: &str = "1:244";
/// Minimum spread between L1 tiers when multipliers collapse after rounding.
pub const L1_TIER_MIN_DELTA_MEI: f64 = 0.000001;

pub const L1_SPEED_MULT_NORMAL: f64 = 1.20;
pub const L1_SPEED_MULT_FAST: f64 = 5.0;
pub const L1_SPEED_MULT_ULTRA: f64 = 15.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1FeeTierQuote {
    pub speed: L1FeeSpeed,
    pub label: String,
    pub detail: String,
    pub fee_mei: f64,
    pub fee_wire: String,
}

#[derive(Debug, Clone)]
pub struct L1FeeTierSet {
    pub wire_bytes: usize,
    pub tiers: Vec<L1FeeTierQuote>,
    pub selected: L1FeeEstimate,
}

fn wire_bytes_from_build(built: &BuildTxResponse) -> WalletResult<usize> {
    let body = built
        .body
        .as_ref()
        .ok_or_else(|| WalletError::Transaction("missing tx body for fee estimate".into()))?;
    Ok(signed_l1_wire_bytes((body.len() / 2).max(1)))
}

pub fn signed_l1_wire_bytes(unsigned_wire_bytes: usize) -> usize {
    unsigned_wire_bytes.saturating_add(L1_LEGACY_SIGNATURE_BYTES)
}

pub fn minimum_l1_fee_estimate(wire_bytes: usize) -> L1FeeEstimate {
    local_fee_from_wire_bytes(wire_bytes.max(1))
}

pub fn l1_fee_mei_for_speed(base_mei: f64, min_mei: f64, speed: L1FeeSpeed) -> f64 {
    let base_mei = base_mei.max(min_mei);
    let target = match speed {
        L1FeeSpeed::Slow => min_mei,
        L1FeeSpeed::Normal => base_mei * L1_SPEED_MULT_NORMAL,
        L1FeeSpeed::Fast => base_mei * L1_SPEED_MULT_FAST,
        L1FeeSpeed::Ultra => base_mei * L1_SPEED_MULT_ULTRA,
    };
    target.max(min_mei)
}

fn estimate_from_mei(fee_mei: f64, wire_bytes: usize, purity: u64, min_mei: f64) -> L1FeeEstimate {
    let fee_mei = crate::hip23::normalize_l1_fee_mei(fee_mei).max(min_mei);
    L1FeeEstimate {
        fee_mei,
        fee_node: format_l1_fee_mei_for_node(fee_mei),
        fee_wire: mei_to_fee_wire(fee_mei),
        wire_bytes,
        purity,
    }
}

fn enforce_distinct_l1_tiers(
    tiers: &mut [L1FeeTierQuote],
    wire_bytes: usize,
    purity: u64,
    min_mei: f64,
) {
    for i in 1..tiers.len() {
        if tiers[i].fee_mei <= tiers[i - 1].fee_mei {
            let bumped =
                crate::hip23::normalize_l1_fee_mei(tiers[i - 1].fee_mei + L1_TIER_MIN_DELTA_MEI);
            let est = estimate_from_mei(bumped, wire_bytes, purity, min_mei);
            tiers[i].fee_mei = est.fee_mei;
            tiers[i].fee_wire = est.fee_wire;
        }
    }
}

pub fn build_l1_fee_tiers(
    base_mei: f64,
    min_mei: f64,
    wire_bytes: usize,
    purity: u64,
) -> Vec<L1FeeTierQuote> {
    let mut tiers: Vec<L1FeeTierQuote> = [
        L1FeeSpeed::Slow,
        L1FeeSpeed::Normal,
        L1FeeSpeed::Fast,
        L1FeeSpeed::Ultra,
    ]
    .into_iter()
    .map(|speed| {
        let raw_mei = l1_fee_mei_for_speed(base_mei, min_mei, speed);
        let est = estimate_from_mei(raw_mei, wire_bytes, purity, min_mei);
        L1FeeTierQuote {
            speed,
            label: speed.label().into(),
            detail: speed.detail().into(),
            fee_mei: est.fee_mei,
            fee_wire: est.fee_wire,
        }
    })
    .collect();
    enforce_distinct_l1_tiers(&mut tiers, wire_bytes, purity, min_mei);
    tiers
}

async fn base_fee_mei(node: &NodeClient, wire_bytes: usize) -> WalletResult<(f64, u64)> {
    let wire_bytes = wire_bytes.max(1);
    match node.query_fee_average(wire_bytes, L1_TX_TYPE).await {
        Ok(resp) => {
            let base = parse_fee_mei_decimal(&resp.feasible)?;
            Ok((base, resp.purity))
        }
        Err(_) => {
            let min = minimum_l1_fee_estimate(wire_bytes);
            Ok((min.fee_mei, min.purity))
        }
    }
}

pub async fn estimate_l1_fee(
    node: &NodeClient,
    wire_bytes: usize,
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeEstimate> {
    let wire_bytes = wire_bytes.max(1);
    let (base_mei, purity) = base_fee_mei(node, wire_bytes).await?;
    let min_mei = minimum_l1_fee_estimate(wire_bytes).fee_mei;
    let fee_mei = l1_fee_mei_for_speed(base_mei, min_mei, speed);
    Ok(estimate_from_mei(fee_mei, wire_bytes, purity, min_mei))
}

async fn estimate_from_build(
    node: &NodeClient,
    built: WalletResult<BuildTxResponse>,
    fallback_wire_bytes: usize,
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeEstimate> {
    let wire_bytes = match built {
        Ok(ref resp) if resp.ret == 0 => wire_bytes_from_build(resp).unwrap_or(fallback_wire_bytes),
        _ => fallback_wire_bytes,
    };
    estimate_l1_fee(node, wire_bytes, speed)
        .await
        .or_else(|_| Ok(fallback_l1_fee(wire_bytes)))
}

pub async fn estimate_hac_l1_fee_tiers(
    node: &NodeClient,
    from: &str,
    to: &str,
    amount_wire: &str,
    amount_mei: f64,
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeTierSet> {
    let probe = wire_mei_for_node(L1_PROBE_FEE_WIRE);
    let service_fee_mei = compute_service_fee_mei(amount_mei);
    let service_fee_wire = if service_fee_mei > 0.0 {
        Some(format_service_fee_amount_wire(service_fee_mei))
    } else {
        None
    };
    let built = if let Some(ref svc_wire) = service_fee_wire {
        node.build_send_hac_tx_actions(
            from,
            &probe,
            &[
                (to, amount_wire),
                (WALLET_TREASURY_ADDRESS, svc_wire.as_str()),
            ],
        )
        .await
    } else {
        node.build_send_hac_tx(from, to, amount_wire, &probe).await
    };
    let wire_bytes = match &built {
        Ok(resp) if resp.ret == 0 => wire_bytes_from_build(resp).unwrap_or(L1_DEFAULT_WIRE_BYTES),
        _ => L1_DEFAULT_WIRE_BYTES,
    };
    let (base_mei, purity) = base_fee_mei(node, wire_bytes).await?;
    let min_mei = minimum_l1_fee_estimate(wire_bytes).fee_mei;
    let tiers = build_l1_fee_tiers(base_mei, min_mei, wire_bytes, purity);
    let selected_mei = tiers
        .iter()
        .find(|t| t.speed == speed)
        .map(|t| t.fee_mei)
        .unwrap_or_else(|| l1_fee_mei_for_speed(base_mei, min_mei, speed));
    Ok(L1FeeTierSet {
        wire_bytes,
        tiers,
        selected: estimate_from_mei(selected_mei, wire_bytes, purity, min_mei),
    })
}

pub async fn estimate_hac_l1_fee(
    node: &NodeClient,
    from: &str,
    to: &str,
    amount_wire: &str,
    amount_mei: f64,
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeEstimate> {
    Ok(
        estimate_hac_l1_fee_tiers(node, from, to, amount_wire, amount_mei, speed)
            .await?
            .selected,
    )
}

pub async fn estimate_hacd_l1_fee(
    node: &NodeClient,
    from: &str,
    to: &str,
    diamond_names: &[String],
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeEstimate> {
    let probe = wire_mei_for_node(L1_PROBE_FEE_WIRE);
    let service_fee = format_service_fee_amount_wire(HACD_SERVICE_FEE_MEI);
    let built = node
        .build_send_diamond_tx_with_service_fee(from, to, diamond_names, &service_fee, &probe)
        .await;
    let fallback = L1_DEFAULT_WIRE_BYTES.saturating_add(diamond_names.len().saturating_sub(1) * 24);
    estimate_from_build(node, built, fallback, speed).await
}

pub async fn estimate_btc_l1_fee(
    node: &NodeClient,
    from: &str,
    to: &str,
    satoshi: u64,
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeEstimate> {
    let probe = wire_mei_for_node(L1_PROBE_FEE_WIRE);
    let service_fee = compute_btc_service_fee_satoshi(satoshi);
    let built = node
        .build_send_btc_tx_actions(
            from,
            &probe,
            &[(to, satoshi), (WALLET_TREASURY_ADDRESS, service_fee)],
        )
        .await;
    estimate_from_build(node, built, L1_DEFAULT_WIRE_BYTES, speed).await
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

    #[test]
    fn signed_size_includes_legacy_signature() {
        assert_eq!(signed_l1_wire_bytes(110), 207);
    }

    #[test]
    fn slow_never_below_minimum() {
        let min = minimum_l1_fee_estimate(166).fee_mei;
        let node_min = crate::hip23::normalize_l1_fee_mei(min);
        let tiers = build_l1_fee_tiers(0.00001, min, 166, L1_DEFAULT_LOWEST_FEE_PURITY);
        assert!((tiers[0].fee_mei - node_min).abs() < 1e-12);
        assert!(tiers[1].fee_mei >= node_min);
        assert!(tiers[2].fee_mei >= tiers[1].fee_mei);
        assert!(tiers[3].fee_mei >= tiers[2].fee_mei);
    }

    #[test]
    fn tier_wires_are_positive() {
        let min = minimum_l1_fee_estimate(166).fee_mei;
        let tiers = build_l1_fee_tiers(0.003, min, 166, 6024);
        for tier in &tiers {
            assert!(tier.fee_mei > 0.0);
            assert!(!tier.fee_wire.is_empty());
            assert_ne!(crate::hip23::wire_mei_for_node(&tier.fee_wire), "0");
        }
    }

    #[test]
    fn small_tx_tiers_keep_sub_milli_spread() {
        let min = minimum_l1_fee_estimate(L1_DEFAULT_WIRE_BYTES).fee_mei;
        assert!(min < 0.001, "raw dynamic min is sub-milli: {min}");
        let base = 0.00012;
        let tiers = build_l1_fee_tiers(
            base,
            min,
            L1_DEFAULT_WIRE_BYTES,
            L1_DEFAULT_LOWEST_FEE_PURITY,
        );
        assert!(tiers[0].fee_mei >= min);
        assert!(tiers[1].fee_mei > tiers[0].fee_mei);
        assert!(tiers[2].fee_mei > tiers[1].fee_mei);
        assert!(tiers[3].fee_mei > tiers[2].fee_mei);
        assert!((tiers[1].fee_mei - 0.000144).abs() < 1e-9);
        assert!((tiers[2].fee_mei - 0.0006).abs() < 1e-9);
        assert!((tiers[3].fee_mei - 0.0018).abs() < 1e-9);
    }

    #[test]
    fn high_base_tiers_stay_dynamic() {
        let min = minimum_l1_fee_estimate(166).fee_mei;
        let tiers = build_l1_fee_tiers(0.005, min, 166, 6024);
        assert!((tiers[0].fee_mei - crate::hip23::normalize_l1_fee_mei(min).max(min)).abs() < 1e-9);
        assert!((tiers[1].fee_mei - 0.006).abs() < 1e-9);
        assert!((tiers[2].fee_mei - 0.025).abs() < 1e-9);
        assert!((tiers[3].fee_mei - 0.075).abs() < 1e-9);
    }
}
