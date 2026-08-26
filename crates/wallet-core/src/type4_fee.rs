//! Dynamic Type 4 (PQC/Hybrid) fee estimation from node fee purity × tx wire size.

use field::{Amount, UNIT_MEI};

use crate::error::{WalletError, WalletResult};
use crate::hip23::{format_l1_fee_mei_for_node, parse_hacash_wire_mei};

/// Node default: ~1:244 on a 166-byte simple L1 tx → purity ≈ 6024.
pub const L1_DEFAULT_LOWEST_FEE_PURITY: u64 = 1_000_000 / 166;

/// Alias kept for Type 4 local fallback (same purity constant as L1 minimum tier).
pub const TYPE4_DEFAULT_LOWEST_FEE_PURITY: u64 = L1_DEFAULT_LOWEST_FEE_PURITY;

/// Mempool minimum signed wire (~5 KB ML-DSA signature payload).
pub const TYPE4_MIN_SIGNED_WIRE_BYTES: usize = 512;

/// Conservative signed-size estimate when only the unsigned body is known.
pub const TYPE4_SIGNATURE_OVERHEAD_BYTES: usize = 5000;

const FEE_HEADROOM: f64 = 1.10;

/// One thing this fee estimate had to guess because the node did not answer.
///
/// Both variants carry the node's own error text verbatim. A reason that has
/// been reduced to "the node was unavailable" cannot be acted on; the string
/// the node actually returned can be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeGuess {
    /// `/query/fee/average` failed, so the purity in this estimate is the
    /// wallet's own compiled-in floor rather than anything the network said.
    PurityFromLocalFloor { node_error: String },
    /// The node could not build the unsigned body, so the size this fee is
    /// priced from is a default rather than a measurement of the transaction
    /// that will actually be signed.
    SizeFromDefault {
        node_error: String,
        assumed_bytes: usize,
    },
    /// The node answered the fee query with a rate far above the wallet's own
    /// floor rate for a transaction this size.
    ///
    /// The fee is still the node's number and is still bound to the signature,
    /// so nothing here changes what gets signed. What changes is that the
    /// wallet stops vouching for it. The review screen used to print "Fee
    /// estimate: Quoted by the node" beside a fee a hostile node had inflated,
    /// which reads as the wallet's endorsement of the number rather than a
    /// note about where it came from.
    NodeQuoteFarAboveFloor {
        /// Rounded, because it is read by a person and not compared.
        multiple: u64,
    },
}

impl FeeGuess {
    /// A sentence for a person, not a log line.
    pub fn reason(&self) -> String {
        match self {
            Self::PurityFromLocalFloor { node_error } => format!(
                "the node did not answer the fee query, so this fee is the wallet's own minimum rather than the current network rate ({node_error})"
            ),
            Self::SizeFromDefault {
                node_error,
                assumed_bytes,
            } => format!(
                "the node did not build the transaction body, so this fee is priced from an assumed {assumed_bytes} bytes rather than the real size ({node_error})"
            ),
            Self::NodeQuoteFarAboveFloor { multiple } => format!(
                "the node asked for about {multiple} times the wallet's own rate for a transaction this size, which is not what an ordinary fee looks like; check this fee against the amount before approving, and if it looks wrong then the node is wrong"
            ),
        }
    }

    /// True when this guess is the wallet inventing a number because the node
    /// would not give one, as opposed to the node giving a number the wallet
    /// does not believe. The two need different sentences in front of a person.
    fn is_wallet_fallback(&self) -> bool {
        matches!(
            self,
            Self::PurityFromLocalFloor { .. } | Self::SizeFromDefault { .. }
        )
    }
}

/// Where the numbers in a fee estimate came from.
///
/// # Why an estimate carries this at all
///
/// The fee path had two fallbacks that ran in silence. `/query/fee/average`
/// failing dropped the estimate to a compiled-in floor purity, and a failed
/// body build dropped it to a default byte count, and in both cases the caller
/// received an ordinary-looking `Ok(estimate)` with no way to tell a measured
/// fee from a guessed one. That is the same defect `PaymentPlan::
/// fast_pay_declined` was added to fix on the routing side: the fallback is
/// right, falling back in silence is not.
///
/// Empty means every number in the estimate was measured. Non-empty means at
/// least one was guessed, and says which and why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeEstimateProvenance {
    guesses: Vec<FeeGuess>,
}

impl FeeEstimateProvenance {
    /// Everything in this estimate was measured against the node.
    pub fn measured() -> Self {
        Self::default()
    }

    pub fn with(mut self, guess: FeeGuess) -> Self {
        if !self.guesses.contains(&guess) {
            self.guesses.push(guess);
        }
        self
    }

    /// True when any number in the estimate is a guess.
    pub fn is_degraded(&self) -> bool {
        !self.guesses.is_empty()
    }

    pub fn guesses(&self) -> &[FeeGuess] {
        &self.guesses
    }

    pub fn reasons(&self) -> Vec<String> {
        self.guesses.iter().map(FeeGuess::reason).collect()
    }

    /// The line to put in front of a person before they pay, or `None` when
    /// there is nothing to warn about.
    ///
    /// Two different situations end up here and they must not share a
    /// sentence. "The wallet made this up because the node was silent" ends
    /// with a fee that may be too low to confirm. "The node named a number the
    /// wallet does not believe" ends with a fee that may be far too high, and
    /// telling that person their fee may be too low is worse than saying
    /// nothing.
    pub fn warning(&self) -> Option<String> {
        if self.guesses.is_empty() {
            return None;
        }
        let reasons = self.reasons().join("; ");
        if self.guesses.iter().all(FeeGuess::is_wallet_fallback) {
            return Some(format!(
                "This fee is an estimate the wallet made without the node: {reasons}. It may be too low to confirm."
            ));
        }
        Some(format!("Check this fee before you approve: {reasons}."))
    }
}

#[derive(Debug, Clone)]
pub struct Type4FeeEstimate {
    pub fee_mei: f64,
    /// Decimal mei string for `Amount::from` / node APIs.
    pub fee_node: String,
    /// Wallet display wire (`whole:frac` millis).
    pub fee_wire: String,
    pub wire_bytes: usize,
    pub purity: u64,
    /// Which of the numbers above were measured and which were guessed.
    pub provenance: FeeEstimateProvenance,
}

impl Type4FeeEstimate {
    pub fn is_degraded(&self) -> bool {
        self.provenance.is_degraded()
    }

    pub fn warning(&self) -> Option<String> {
        self.provenance.warning()
    }
}

pub fn mei_to_fee_wire(mei: f64) -> String {
    let decimal = format_l1_fee_mei_for_node(mei);
    Amount::from(&decimal)
        .map(|amount| amount.to_fin_string())
        .unwrap_or_else(|_| {
            Amount::from("1:244")
                .expect("valid fallback fee")
                .to_fin_string()
        })
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

/// The wallet's own floor fee for a size, asked of nobody.
///
/// This is legitimately local when it is used as the *minimum* an estimate may
/// not fall below. It is a guess only when it is used as the estimate itself
/// after the node refused to answer, and that case must be built through
/// [`local_fee_from_wire_bytes_after_node_error`] so the caller can see it.
pub fn local_fee_from_wire_bytes(wire_bytes: usize) -> Type4FeeEstimate {
    let purity = TYPE4_DEFAULT_LOWEST_FEE_PURITY;
    let fee_238 = (purity as u128)
        .saturating_mul(wire_bytes as u128)
        .min(u64::MAX as u128) as u64;
    fee_from_unit238(fee_238.max(1), wire_bytes, purity)
}

/// The same floor fee, marked as what it is: a fee the wallet invented because
/// the node did not answer.
pub fn local_fee_from_wire_bytes_after_node_error(
    wire_bytes: usize,
    node_error: &str,
) -> Type4FeeEstimate {
    let mut est = local_fee_from_wire_bytes(wire_bytes);
    est.provenance = est.provenance.with(FeeGuess::PurityFromLocalFloor {
        node_error: node_error.to_owned(),
    });
    est
}

fn fee_from_unit238(fee_238: u64, wire_bytes: usize, purity: u64) -> Type4FeeEstimate {
    let amt = Amount::unit238(fee_238);
    let base_mei = unsafe { amt.to_unit_float(UNIT_MEI) };
    let fee_mei = base_mei * FEE_HEADROOM;
    let fee_node = format_l1_fee_mei_for_node(fee_mei);
    let fee_wire = mei_to_fee_wire(fee_mei);
    Type4FeeEstimate {
        fee_mei,
        fee_node,
        fee_wire,
        wire_bytes,
        purity,
        provenance: FeeEstimateProvenance::measured(),
    }
}

pub fn fee_from_node_average(
    feasible_mei: &str,
    wire_bytes: usize,
    purity: u64,
) -> WalletResult<Type4FeeEstimate> {
    let base = parse_fee_mei_decimal(feasible_mei)?;
    let fee_mei = base * FEE_HEADROOM;
    Ok(Type4FeeEstimate {
        fee_mei,
        fee_node: format_l1_fee_mei_for_node(fee_mei),
        fee_wire: mei_to_fee_wire(fee_mei),
        wire_bytes,
        purity,
        provenance: FeeEstimateProvenance::measured(),
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
        assert!(
            est.fee_mei < 1.0,
            "Type 4 fee must be well below 1 HAC at minimum purity"
        );
    }

    #[test]
    fn local_fee_matches_node_order_of_magnitude() {
        let local = local_fee_from_wire_bytes(5500);
        assert!(local.fee_mei > 0.003 && local.fee_mei < 0.01);
    }

    #[test]
    fn mei_wire_roundtrip_small_fee() {
        let wire = mei_to_fee_wire(0.00365);
        assert_eq!(wire, "365:243");
        assert!((fee_mei_from_wire(&wire) - 0.00365).abs() < 0.000001);
    }
}
