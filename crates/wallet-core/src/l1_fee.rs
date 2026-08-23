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
    FeeEstimateProvenance, FeeGuess, L1_DEFAULT_LOWEST_FEE_PURITY, Type4FeeEstimate,
    local_fee_from_wire_bytes, mei_to_fee_wire, parse_fee_mei_decimal,
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

impl L1FeeTierSet {
    /// True when any number behind these tiers is a guess rather than a
    /// measurement. Every tier is derived from the same base rate and the same
    /// size, so one answer covers the whole set.
    pub fn is_degraded(&self) -> bool {
        self.selected.is_degraded()
    }

    pub fn warning(&self) -> Option<String> {
        self.selected.warning()
    }
}

fn wire_bytes_from_build(built: &BuildTxResponse) -> WalletResult<usize> {
    let body = built
        .body
        .as_ref()
        .ok_or_else(|| WalletError::Transaction("missing tx body for fee estimate".into()))?;
    Ok(signed_l1_wire_bytes((body.len() / 2).max(1)))
}

pub fn signed_l1_wire_bytes(unsigned_wire_bytes: usize) -> usize {
    signed_l1_wire_bytes_for_signatures(unsigned_wire_bytes, 1)
}

pub fn signed_l1_wire_bytes_for_signatures(
    unsigned_wire_bytes: usize,
    signature_count: usize,
) -> usize {
    unsigned_wire_bytes.saturating_add(L1_LEGACY_SIGNATURE_BYTES.saturating_mul(signature_count))
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

fn estimate_from_mei(
    fee_mei: f64,
    wire_bytes: usize,
    purity: u64,
    min_mei: f64,
    provenance: FeeEstimateProvenance,
) -> L1FeeEstimate {
    let fee_mei = crate::hip23::normalize_l1_fee_mei(fee_mei).max(min_mei);
    L1FeeEstimate {
        fee_mei,
        fee_node: format_l1_fee_mei_for_node(fee_mei),
        fee_wire: mei_to_fee_wire(fee_mei),
        wire_bytes,
        purity,
        provenance,
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
            let est = estimate_from_mei(
                bumped,
                wire_bytes,
                purity,
                min_mei,
                FeeEstimateProvenance::measured(),
            );
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
        let est = estimate_from_mei(
            raw_mei,
            wire_bytes,
            purity,
            min_mei,
            FeeEstimateProvenance::measured(),
        );
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

/// The base rate this fee is priced from, and an honest account of where it
/// came from.
///
/// This used to answer `Ok((base, purity))` whether or not the node replied,
/// which meant a caller could not tell the network's rate from the wallet's own
/// compiled-in floor. The fallback stays, because refusing to quote a fee at all
/// when the node blinks is worse; what changes is that the fallback now says so.
async fn base_fee_mei(
    node: &NodeClient,
    wire_bytes: usize,
    tx_type: u8,
) -> WalletResult<(f64, u64, FeeEstimateProvenance)> {
    let wire_bytes = wire_bytes.max(1);
    let node_error = match node.query_fee_average(wire_bytes, tx_type).await {
        // A `ret == 0` whose fee will not parse is a node that did not answer
        // the question, so it takes the same audible fallback rather than
        // failing the whole quote.
        Ok(resp) => match parse_fee_mei_decimal(&resp.feasible) {
            Ok(base) => return Ok((base, resp.purity, FeeEstimateProvenance::measured())),
            Err(err) => err.to_string(),
        },
        Err(err) => err.to_string(),
    };
    let min = minimum_l1_fee_estimate(wire_bytes);
    Ok((
        min.fee_mei,
        min.purity,
        FeeEstimateProvenance::measured().with(FeeGuess::PurityFromLocalFloor { node_error }),
    ))
}

pub async fn estimate_l1_fee(
    node: &NodeClient,
    wire_bytes: usize,
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeEstimate> {
    estimate_l1_fee_for_type(node, wire_bytes, speed, L1_TX_TYPE).await
}

pub async fn estimate_l1_fee_for_type(
    node: &NodeClient,
    wire_bytes: usize,
    speed: L1FeeSpeed,
    tx_type: u8,
) -> WalletResult<L1FeeEstimate> {
    estimate_l1_fee_for_type_with_provenance(
        node,
        wire_bytes,
        speed,
        tx_type,
        FeeEstimateProvenance::measured(),
    )
    .await
}

/// The same estimate, carrying forward guesses a caller already had to make
/// before it got here (a size it could not measure, most often).
pub async fn estimate_l1_fee_for_type_with_provenance(
    node: &NodeClient,
    wire_bytes: usize,
    speed: L1FeeSpeed,
    tx_type: u8,
    inherited: FeeEstimateProvenance,
) -> WalletResult<L1FeeEstimate> {
    let wire_bytes = wire_bytes.max(1);
    let (base_mei, purity, mut provenance) = base_fee_mei(node, wire_bytes, tx_type).await?;
    for guess in inherited.guesses() {
        provenance = provenance.with(guess.clone());
    }
    let min_mei = minimum_l1_fee_estimate(wire_bytes).fee_mei;
    let fee_mei = l1_fee_mei_for_speed(base_mei, min_mei, speed);
    Ok(estimate_from_mei(
        fee_mei, wire_bytes, purity, min_mei, provenance,
    ))
}

/// The size to price from, and whether it is a measurement or a default.
///
/// The build probe exists so the fee is charged against the bytes that will
/// actually be signed. When it fails the code still has to produce a number, so
/// it uses `L1_DEFAULT_WIRE_BYTES`; the point of returning the provenance
/// alongside is that a default is no longer indistinguishable from a measured
/// body.
fn wire_bytes_with_provenance(
    built: &WalletResult<BuildTxResponse>,
    fallback_wire_bytes: usize,
) -> (usize, FeeEstimateProvenance) {
    let node_error = match built {
        Ok(resp) if resp.ret == 0 => match wire_bytes_from_build(resp) {
            Ok(bytes) => return (bytes, FeeEstimateProvenance::measured()),
            Err(err) => err.to_string(),
        },
        Ok(resp) => resp
            .err
            .clone()
            .or_else(|| resp.error.clone())
            .or_else(|| resp.message.clone())
            .unwrap_or_else(|| format!("build transaction failed (ret={})", resp.ret)),
        Err(err) => err.to_string(),
    };
    (
        fallback_wire_bytes,
        FeeEstimateProvenance::measured().with(FeeGuess::SizeFromDefault {
            node_error,
            assumed_bytes: fallback_wire_bytes,
        }),
    )
}

async fn estimate_from_build(
    node: &NodeClient,
    built: WalletResult<BuildTxResponse>,
    fallback_wire_bytes: usize,
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeEstimate> {
    let (wire_bytes, size_provenance) = wire_bytes_with_provenance(&built, fallback_wire_bytes);
    match estimate_l1_fee_for_type_with_provenance(
        node,
        wire_bytes,
        speed,
        L1_TX_TYPE,
        size_provenance.clone(),
    )
    .await
    {
        Ok(est) => Ok(est),
        Err(err) => Ok(fallback_l1_fee_after_node_error(
            wire_bytes,
            &err.to_string(),
            size_provenance,
        )),
    }
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
    let (wire_bytes, size_provenance) = wire_bytes_with_provenance(&built, L1_DEFAULT_WIRE_BYTES);
    let (base_mei, purity, mut provenance) = base_fee_mei(node, wire_bytes, L1_TX_TYPE).await?;
    for guess in size_provenance.guesses() {
        provenance = provenance.with(guess.clone());
    }
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
        selected: estimate_from_mei(selected_mei, wire_bytes, purity, min_mei, provenance),
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

pub async fn estimate_native_asset_l1_fee(
    node: &NodeClient,
    from: &str,
    to: &str,
    serial: u64,
    amount: u64,
    speed: L1FeeSpeed,
) -> WalletResult<L1FeeEstimate> {
    let probe = wire_mei_for_node(L1_PROBE_FEE_WIRE);
    let built = node
        .build_send_native_asset_tx(from, to, serial, amount, &probe)
        .await;
    estimate_from_build(node, built, L1_DEFAULT_WIRE_BYTES, speed).await
}

/// The bare hardcoded fee, with no provenance worth trusting.
///
/// **Private, deliberately.** This stamps `measured()` because the only caller
/// that may hand it out overwrites the provenance immediately, and a value
/// that says "measured" while carrying a compiled-in constant is precisely the
/// bug this module was rewritten to remove. Leaving it public was a trap: the
/// next caller to reach for the obvious name would have reintroduced the
/// silent fallback while every test stayed green.
///
/// Anything reached by way of a node failure must come through
/// [`fallback_l1_fee_after_node_error`], which records what was guessed and
/// why.
fn fallback_l1_fee(wire_bytes: usize) -> L1FeeEstimate {
    L1FeeEstimate {
        fee_mei: L1_DEFAULT_FEE_MEI,
        fee_node: wire_mei_for_node(L1_PROBE_FEE_WIRE),
        fee_wire: L1_PROBE_FEE_WIRE.to_string(),
        wire_bytes,
        purity: L1_DEFAULT_LOWEST_FEE_PURITY,
        provenance: FeeEstimateProvenance::measured(),
    }
}

/// The hardcoded default fee, marked as the guess it is.
///
/// `fallback_l1_fee` on its own is indistinguishable from a real quote once it
/// reaches a caller, which is exactly how a node outage used to turn into a
/// silently under-priced transaction. Anything reached by way of a node failure
/// must come through here instead.
pub fn fallback_l1_fee_after_node_error(
    wire_bytes: usize,
    node_error: &str,
    inherited: FeeEstimateProvenance,
) -> L1FeeEstimate {
    let mut est = fallback_l1_fee(wire_bytes);
    let mut provenance = FeeEstimateProvenance::measured().with(FeeGuess::PurityFromLocalFloor {
        node_error: node_error.to_owned(),
    });
    for guess in inherited.guesses() {
        provenance = provenance.with(guess.clone());
    }
    est.provenance = provenance;
    est
}

pub fn format_l1_fee_label(est: &L1FeeEstimate) -> String {
    format!("~{} HAC", est.fee_node)
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
        assert_eq!(signed_l1_wire_bytes_for_signatures(110, 2), 304);
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
