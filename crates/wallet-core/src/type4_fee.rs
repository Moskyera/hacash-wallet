//! Dynamic Type 4 (PQC/Hybrid) fee estimation from node fee purity × tx wire size.

use field::{Amount, UNIT_MEI};

use crate::error::{WalletError, WalletResult};
use crate::hip23::{format_mei_for_node, parse_hacash_wire_mei};

/// Node default: ~1:244 on a 166-byte simple tx → purity ≈ 6024.
pub const TYPE4_DEFAULT_LOWEST_FEE_PURITY: u64 = 10_000_00 / 166;

/// Mempool minimum signed wire (~5 KB ML-DSA signature payload).
pub const TYPE4_MIN_SIGNED_WIRE_BYTES: usize = 512;

/// Conservative signed-size estimate when only the unsigned body is known.
pub const TYPE4_SIGNATURE_OVERHEAD_BYTES: usize = 5000;

const FEE_HEADROOM: f64 = 1.10;

#[derive(Debug, Clone)]
pub struct Type4FeeEstimate {
    pub fee_mei: f64,
    /// Decimal mei string for `Amount::from` / node APIs.
    pub fee_node: String,
    /// Wallet display wire (`whole:frac` millis).
    pub fee_wire: String,
    pub wire_bytes: usize,
    pub purity: u64,
}

pub fn mei_to_fee_wire(mei: f64) -> String {
    let rounded = (mei * 1000.0).round() / 1000.0;
    let mut whole = rounded.floor();
    let mut frac = ((rounded - whole) * 1000.0).round();
    if frac >= 1000.0 {
        whole += 1.0;
        frac = 0.0;
    }
    format!("{}:{:03}", whole as u64, frac as u64)
}

pub fn parse_fee_mei_decimal(raw: &str) -> WalletResult<f64> {
    let v: f64 = raw
        .trim()
        .parse()
        .map_err(|_| WalletError::Other(format!("invalid fee mei: {raw}")))?;
    if v <= 0.0 {
        return Err(WalletError::Other("fee must be positive".into()));
    }
    Ok(v)
}

pub fn estimate_signed_wire_bytes(unsigned_body_bytes: usize) -> usize {
    unsigned_body_bytes
        .saturating_add(TYPE4_SIGNATURE_OVERHEAD_BYTES)
        .max(TYPE4_MIN_SIGNED_WIRE_BYTES)
}

pub fn local_fee_from_wire_bytes(wire_bytes: usize) -> Type4FeeEstimate {
    let purity = TYPE4_DEFAULT_LOWEST_FEE_PURITY;
    let fee_238 = (purity as u128)
        .saturating_mul(wire_bytes as u128)
        .min(u64::MAX as u128) as u64;
    fee_from_unit238(fee_238.max(1), wire_bytes, purity)
}

fn fee_from_unit238(fee_238: u64, wire_bytes: usize, purity: u64) -> Type4FeeEstimate {
    let amt = Amount::unit238(fee_238);
    let base_mei = unsafe { amt.to_unit_float(UNIT_MEI) };
    let fee_mei = base_mei * FEE_HEADROOM;
    let fee_node = format_mei_for_node(fee_mei);
    let fee_wire = mei_to_fee_wire(fee_mei);
    Type4FeeEstimate {
        fee_mei,
        fee_node,
        fee_wire,
        wire_bytes,
        purity,
    }
}

pub fn fee_from_node_average(feasible_mei: &str, wire_bytes: usize, purity: u64) -> WalletResult<Type4FeeEstimate> {
    let base = parse_fee_mei_decimal(feasible_mei)?;
    let fee_mei = base * FEE_HEADROOM;
    Ok(Type4FeeEstimate {
        fee_mei,
        fee_node: format_mei_for_node(fee_mei),
        fee_wire: mei_to_fee_wire(fee_mei),
        wire_bytes,
        purity,
    })
}

pub fn fee_mei_from_wire(fee_wire: &str) -> f64 {
    parse_hacash_wire_mei(fee_wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_api_fee_scale_matches_mei() {
        // nodeapi.hacash.org: consumption=5500 → feasible "0.0033132" mei
        let est = fee_from_node_average("0.0033132", 5500, 6024).unwrap();
        assert!(est.fee_mei > 0.003 && est.fee_mei < 0.01);
        assert!(est.fee_mei < 1.0, "Type 4 fee must be well below 1 HAC at minimum purity");
    }

    #[test]
    fn local_fee_matches_node_order_of_magnitude() {
        let local = local_fee_from_wire_bytes(5500);
        assert!(local.fee_mei > 0.003 && local.fee_mei < 0.01);
    }

    #[test]
    fn mei_wire_roundtrip_small_fee() {
        let wire = mei_to_fee_wire(0.00365);
        assert_eq!(wire, "0:004");
        assert!((fee_mei_from_wire(&wire) - 0.004).abs() < 0.0001);
    }
}