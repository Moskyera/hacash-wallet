//! Proof that an exact signed transaction can never be inside a valid block.
//!
//! # Why this exists
//!
//! A durable chain operation that has been signed is a liability: the Hub must
//! assume the bytes may have reached the chain until it can show otherwise.
//! That assumption is what makes `RecoveryRequired` safe — and what makes it
//! permanent. Two live runs on the private chain-7 pilot ended with a Hub
//! latched forever by one transaction the fullnode would never accept.
//!
//! Abandoning such an operation so a correct replacement can be signed is the
//! single most dangerous transition a Hub could make. If the abandoned
//! transaction *did* execute, the replacement double-submits. So abandonment
//! must never rest on "we did not observe it", which is only ever evidence of
//! where we looked. It must rest on a rule of the consensus itself, under
//! which the bytes are inadmissible and therefore cannot be in any block.
//!
//! # What counts as a proof
//!
//! A submission-time rule alone is not enough: a node that refuses to relay a
//! transaction says nothing about a miner that includes it directly. A proof
//! has to come from a rule applied when a *block* is validated, because that
//! is what every node runs over every block before accepting it.
//!
//! The one rule implemented here satisfies both halves:
//!
//! | where | rule |
//! |---|---|
//! | `chain/src/check.rs:103` | submission refuses `tx.timestamp() > curtimes()` |
//! | `chain/src/verify.rs:75`  | block verification refuses the same |
//!
//! Because the second is a block-verification rule, no node running this
//! consensus code accepts a block carrying a transaction stamped ahead of that
//! node's clock. A transaction stamped ahead of both the chain's own tip and
//! the Hub's clock is therefore not in the chain any correct node has built.
//!
//! The Hub cannot read the fullnode's clock directly, so the proof is taken
//! against the two readings it does have — the chain tip's own timestamp and
//! the Hub's clock at the moment the tip was read — with a margin as wide as
//! the node-clock skew the Hub already tolerates everywhere else. Clearing
//! both readings *plus* that margin is what makes the conclusion robust rather
//! than a race against a second hand.
//!
//! # What this is deliberately not
//!
//! There is no catch-all arm and no operator override. A transaction no listed
//! rule proves inadmissible is not abandonable, full stop — the caller is told
//! which rules were tried and why each one failed to apply. Adding a new
//! structural impossibility means adding a variant to [`InadmissibilityRule`]
//! and an evaluator to [`prove_transaction_inadmissible`]; it cannot be done
//! by relaxing anything here.
//!
//! A proof from this module is a necessary condition for abandonment, never a
//! sufficient one. The caller must still read the chain one last time and find
//! the transaction absent.

use serde::{Deserialize, Serialize};

use crate::error::{HubError, HubResult};
use crate::node::{
    FULLNODE_MAX_FUTURE_SKEW_SECONDS, FULLNODE_MAX_TIP_AGE_SECONDS, FullnodeCapabilitiesV1,
};

/// Largest signed transaction this gate will decode. The same ceiling the
/// channel transaction readers use, so nothing decodable elsewhere becomes
/// undecodable here.
pub const MAX_INADMISSIBLE_TRANSACTION_BYTES: usize =
    crate::l1_channel::MAX_CHANNEL_TRANSACTION_BYTES;

/// How far ahead of the Hub's own readings a timestamp has to be before the
/// fullnode's clock comparison is settled beyond argument.
///
/// The rule the fullnode applies is `tx.timestamp() > curtimes()`, read from
/// *its* clock at *its* moment of validation. The Hub adds the widest node
/// clock skew it tolerates anywhere else on top of its own readings, so a
/// timestamp that clears the margin is one no plausibly-clocked node running
/// this consensus code could have accepted.
pub const INADMISSIBILITY_CLOCK_MARGIN_SECONDS: u64 = FULLNODE_MAX_FUTURE_SKEW_SECONDS;

/// Every structural impossibility this gate can prove.
///
/// One variant per consensus rule. A rule belongs here only when it is applied
/// during *block verification*, so that satisfying it excludes the transaction
/// from every valid block rather than merely from one node's relay path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InadmissibilityRule {
    /// The transaction is stamped ahead of the chain's clock.
    ///
    /// `chain/src/check.rs:103` refuses it at submission and
    /// `chain/src/verify.rs:75` refuses any block that carries it.
    FutureTimestamp,
}

impl InadmissibilityRule {
    /// Every rule the gate knows, in the order they are attempted.
    ///
    /// This is the whole list. A new structural impossibility is added by
    /// extending this slice and giving it an arm in
    /// [`prove_transaction_inadmissible`], which the compiler then requires.
    /// Nothing is abandonable that no entry here proves.
    pub const ALL: &'static [Self] = &[Self::FutureTimestamp];

    /// Stable machine name. It is written into the durable record, so it is
    /// part of the on-disk format and must not change once shipped.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FutureTimestamp => "future_timestamp",
        }
    }

    /// Read a rule back from a durable record. An unrecognised name is not a
    /// rule, so a record naming one carries no proof.
    pub fn from_name(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|rule| rule.as_str() == value)
    }
}

/// The chain-side half of a proof: what the node said the world looked like at
/// the moment the proof was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainTipEvidence {
    /// Timestamp of the chain's own tip block.
    pub tip_timestamp_unix: u64,
    /// The Hub's clock when that tip was read.
    pub observed_unix: u64,
    /// Height of that tip.
    pub observed_height: u64,
}

impl ChainTipEvidence {
    pub fn from_capabilities(capabilities: &FullnodeCapabilitiesV1) -> Self {
        Self {
            tip_timestamp_unix: capabilities.tip_timestamp_unix,
            observed_unix: capabilities.observed_unix,
            observed_height: capabilities.height,
        }
    }

    /// Refuse to reason about a tip that is not usable evidence.
    ///
    /// `FullnodeNode::capabilities` already enforces every one of these when it
    /// parses the response. They are re-checked because a proof is only worth
    /// as much as the reading behind it, and this module must not depend on
    /// having been handed a value that came from there.
    fn validate(&self) -> HubResult<()> {
        if self.tip_timestamp_unix == 0 || self.observed_unix == 0 || self.observed_height == 0 {
            return Err(HubError::Node(
                "chain tip evidence is incomplete; no admissibility proof can rest on it".into(),
            ));
        }
        if self.tip_timestamp_unix
            > self
                .observed_unix
                .saturating_add(FULLNODE_MAX_FUTURE_SKEW_SECONDS)
        {
            return Err(HubError::Node(
                "chain tip timestamp is ahead of the Hub clock; no admissibility proof can rest on it".into(),
            ));
        }
        if self.observed_unix.saturating_sub(self.tip_timestamp_unix) > FULLNODE_MAX_TIP_AGE_SECONDS
        {
            return Err(HubError::Node(
                "chain tip evidence is stale; no admissibility proof can rest on it".into(),
            ));
        }
        Ok(())
    }

    /// The highest clock reading the Hub is willing to attribute to the
    /// fullnode. Both of its own readings, and then the skew margin on top.
    fn clock_ceiling(&self) -> u64 {
        self.tip_timestamp_unix
            .max(self.observed_unix)
            .saturating_add(INADMISSIBILITY_CLOCK_MARGIN_SECONDS)
    }
}

/// A completed proof. Everything needed to re-check the conclusion later,
/// without the node that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InadmissibilityProof {
    pub rule: InadmissibilityRule,
    /// The exact arithmetic in words, kept verbatim in the durable record so
    /// the abandonment is auditable from the state file alone.
    pub detail: String,
    /// Hash of the exact bytes the proof is about.
    pub transaction_hash: String,
    /// Timestamp read out of those bytes, not copied from anywhere else.
    pub transaction_timestamp: u64,
    pub tip: ChainTipEvidence,
}

/// What the exact signed bytes actually say. Read from the bytes themselves;
/// nothing here is taken from the durable record that stores them.
struct SignedTransactionFacts {
    hash: String,
    timestamp: u64,
}

/// Prove that these exact bytes cannot be inside a valid block.
///
/// The bytes are decoded, required to hash to `expected_transaction_hash`, and
/// required to carry a signature that verifies — a record whose bytes are not
/// the transaction it claims, or are not properly signed, is a corrupt record,
/// and nothing may be abandoned on corrupt evidence.
///
/// Every known rule is then attempted. The first that applies is the proof.
/// If none applies the error names each rule and why it did not, and the
/// caller must leave the operation exactly where it is.
pub fn prove_transaction_inadmissible(
    signed_transaction_hex: &str,
    expected_transaction_hash: &str,
    capabilities: &FullnodeCapabilitiesV1,
) -> HubResult<InadmissibilityProof> {
    let tip = ChainTipEvidence::from_capabilities(capabilities);
    tip.validate()?;
    let facts = read_exact_signed_transaction(signed_transaction_hex, expected_transaction_hash)?;

    let mut refusals = Vec::new();
    // One arm per rule. There is deliberately no `_ =>` here: a rule that is
    // added has to be evaluated, and a transaction no rule proves inadmissible
    // falls through to the refusal below.
    for rule in InadmissibilityRule::ALL.iter().copied() {
        let attempt = match rule {
            InadmissibilityRule::FutureTimestamp => prove_future_timestamp(&facts, &tip),
        };
        match attempt {
            Ok(detail) => {
                return Ok(InadmissibilityProof {
                    rule,
                    detail,
                    transaction_hash: facts.hash,
                    transaction_timestamp: facts.timestamp,
                    tip,
                });
            }
            Err(reason) => refusals.push(format!("{}: {reason}", rule.as_str())),
        }
    }

    Err(HubError::State(format!(
        "no consensus rule proves transaction {} inadmissible, so it may still be mined and must not be abandoned ({})",
        facts.hash,
        refusals.join("; ")
    )))
}

/// `chain/src/check.rs:103` and `chain/src/verify.rs:75`.
///
/// Both compare the transaction's timestamp against the validating node's own
/// clock. Clearing the Hub's two readings plus the skew margin means no node
/// with a plausible clock has accepted a block carrying these bytes.
fn prove_future_timestamp(
    facts: &SignedTransactionFacts,
    tip: &ChainTipEvidence,
) -> Result<String, String> {
    let ceiling = tip.clock_ceiling();
    if facts.timestamp <= ceiling {
        return Err(format!(
            "timestamp {} is at or below the chain clock ceiling {} (tip {} at height {}, Hub clock {}, +{}s margin), so a node could still accept it",
            facts.timestamp,
            ceiling,
            tip.tip_timestamp_unix,
            tip.observed_height,
            tip.observed_unix,
            INADMISSIBILITY_CLOCK_MARGIN_SECONDS
        ));
    }
    Ok(format!(
        "transaction timestamp {} exceeds the chain clock ceiling {} (tip {} at height {}, Hub clock {}, +{}s margin); chain/src/check.rs refuses it at submission and chain/src/verify.rs refuses any block that carries it, so it is in no valid block",
        facts.timestamp,
        ceiling,
        tip.tip_timestamp_unix,
        tip.observed_height,
        tip.observed_unix,
        INADMISSIBILITY_CLOCK_MARGIN_SECONDS
    ))
}

fn read_exact_signed_transaction(
    signed_transaction_hex: &str,
    expected_transaction_hash: &str,
) -> HubResult<SignedTransactionFacts> {
    if expected_transaction_hash.trim().is_empty() {
        return Err(HubError::State(
            "admissibility proof needs the exact transaction hash".into(),
        ));
    }
    let raw = hex::decode(signed_transaction_hex)
        .map_err(|_| HubError::State("stored transaction bytes are not hex".into()))?;
    if raw.is_empty() || raw.len() > MAX_INADMISSIBLE_TRANSACTION_BYTES {
        return Err(HubError::State(
            "stored transaction bytes are not a decodable transaction".into(),
        ));
    }
    crate::protocol_registry::ensure_hacash_protocol_setup();
    let (transaction, consumed) =
        protocol::transaction::transaction_create(&raw).map_err(|error| {
            HubError::State(format!("stored transaction bytes are invalid: {error}"))
        })?;
    if consumed != raw.len() {
        return Err(HubError::State(
            "stored transaction bytes carry trailing data".into(),
        ));
    }
    let hash = hex::encode(transaction.hash().as_bytes());
    if !hash.eq_ignore_ascii_case(expected_transaction_hash) {
        return Err(HubError::State(
            "stored transaction bytes do not hash to the recorded transaction".into(),
        ));
    }
    transaction.verify_signature().map_err(|error| {
        HubError::State(format!(
            "stored transaction signature does not verify: {error}"
        ))
    })?;
    Ok(SignedTransactionFacts {
        hash,
        timestamp: transaction.timestamp().uint(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(now: u64) -> ChainTipEvidence {
        ChainTipEvidence {
            tip_timestamp_unix: now,
            observed_unix: now,
            observed_height: 900_000,
        }
    }

    fn facts(timestamp: u64) -> SignedTransactionFacts {
        SignedTransactionFacts {
            hash: "ab".repeat(32),
            timestamp,
        }
    }

    #[test]
    fn a_timestamp_the_chain_could_still_accept_is_not_a_proof() {
        let now = 1_786_831_000;
        // Already mined-able.
        assert!(prove_future_timestamp(&facts(now - 10), &tip(now)).is_err());
        // Ahead of the tip, but inside the skew the Hub tolerates: a node with
        // a slightly fast clock could accept it, so it proves nothing.
        assert!(prove_future_timestamp(&facts(now + 1), &tip(now)).is_err());
        assert!(
            prove_future_timestamp(
                &facts(now + INADMISSIBILITY_CLOCK_MARGIN_SECONDS),
                &tip(now)
            )
            .is_err()
        );
    }

    #[test]
    fn a_timestamp_past_the_clock_ceiling_is_a_proof() {
        let now = 1_786_831_000;
        let detail = prove_future_timestamp(
            &facts(now + INADMISSIBILITY_CLOCK_MARGIN_SECONDS + 1),
            &tip(now),
        )
        .expect("past the ceiling is inadmissible");
        assert!(detail.contains("chain/src/verify.rs"));

        // The exact live defect: 1791527729 against a ~1786831000 clock.
        let detail = prove_future_timestamp(&facts(1_791_527_729), &tip(1_786_831_000))
            .expect("the live poisoned finalize is inadmissible");
        assert!(detail.contains("1791527729"));
    }

    #[test]
    fn the_ceiling_takes_the_later_of_the_two_readings() {
        // A tip that trails the Hub clock must not lower the ceiling: the
        // Hub's own clock is the later reading and the node's is at least
        // as late as its tip.
        let evidence = ChainTipEvidence {
            tip_timestamp_unix: 1_786_830_000,
            observed_unix: 1_786_831_000,
            observed_height: 900_000,
        };
        assert_eq!(
            evidence.clock_ceiling(),
            1_786_831_000 + INADMISSIBILITY_CLOCK_MARGIN_SECONDS
        );
        assert!(
            prove_future_timestamp(
                &facts(1_786_830_000 + INADMISSIBILITY_CLOCK_MARGIN_SECONDS + 1),
                &evidence
            )
            .is_err(),
            "clearing only the trailing tip is not a proof"
        );
    }

    #[test]
    fn unusable_tip_evidence_is_refused_before_any_rule_runs() {
        let now = 1_786_831_000;
        assert!(
            ChainTipEvidence {
                tip_timestamp_unix: 0,
                observed_unix: now,
                observed_height: 900_000,
            }
            .validate()
            .is_err()
        );
        assert!(
            ChainTipEvidence {
                tip_timestamp_unix: now,
                observed_unix: now,
                observed_height: 0,
            }
            .validate()
            .is_err()
        );
        // Stale beyond the freshness policy.
        assert!(
            ChainTipEvidence {
                tip_timestamp_unix: now - FULLNODE_MAX_TIP_AGE_SECONDS - 1,
                observed_unix: now,
                observed_height: 900_000,
            }
            .validate()
            .is_err()
        );
        // A tip claiming to be from the future beyond the tolerated skew.
        assert!(
            ChainTipEvidence {
                tip_timestamp_unix: now + FULLNODE_MAX_FUTURE_SKEW_SECONDS + 1,
                observed_unix: now,
                observed_height: 900_000,
            }
            .validate()
            .is_err()
        );
        assert!(tip(now).validate().is_ok());
    }

    #[test]
    fn rule_names_round_trip_and_are_closed() {
        for rule in InadmissibilityRule::ALL.iter().copied() {
            assert_eq!(InadmissibilityRule::from_name(rule.as_str()), Some(rule));
        }
        // No catch-all: an unknown name is not a rule, and a durable record
        // naming one cannot be read back as a proof.
        assert_eq!(InadmissibilityRule::from_name("operator_override"), None);
        assert_eq!(InadmissibilityRule::from_name("force"), None);
        assert_eq!(InadmissibilityRule::from_name(""), None);
    }

    #[test]
    fn bytes_that_are_not_the_recorded_transaction_are_refused() {
        assert!(read_exact_signed_transaction("", &"ab".repeat(32)).is_err());
        assert!(read_exact_signed_transaction("zz", &"ab".repeat(32)).is_err());
        assert!(read_exact_signed_transaction("00", "").is_err());
    }
}
