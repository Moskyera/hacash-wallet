//! HIP-23 wallet pre-sign checks (subset of wallet checklist).
//! Full spec: hacash/doc HIP/protocol/hip-23

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

pub const ISTANBUL_HEIGHT: u64 = 765_432;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hip23SendCheck {
    pub ok: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Type3CheckInput {
    pub tx_type: u8,
    pub chain_height: u64,
    pub gas_max: u64,
    pub has_asset_tex: bool,
    pub ast_depth: u32,
    pub guard_only: bool,
    pub action_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeightScopeInput {
    pub start: u64,
    pub end: u64,
    pub guard_before_debit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceFloorInput {
    pub floor_hacash_mei: f64,
    pub debit_before_floor: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hip23PatternCheck {
    pub pattern: String,
    pub check: Hip23SendCheck,
}

/// Default L1 fee (wallet millis wire `1:244`).
pub const L1_DEFAULT_FEE_MEI: f64 = 1.244;

pub fn validate_simple_l1_send(
    to_address: &str,
    amount_mei: f64,
    balance_mei: f64,
    fee_mei: f64,
) -> WalletResult<Hip23SendCheck> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if !verify_hacash_address(to_address) {
        errors.push("Invalid Hacash address format".into());
    }
    if amount_mei <= 0.0 {
        errors.push("Amount must be positive".into());
    }
    if amount_mei + fee_mei > balance_mei {
        errors.push(format!(
            "Insufficient balance: need {:.3} HAC (amount + fee), have {:.3}",
            amount_mei + fee_mei,
            balance_mei
        ));
    }
    if amount_mei >= 100.0 {
        warnings.push("Large transfer: confirm YubiKey/biometric if enabled".into());
    }

    let ok = errors.is_empty();
    if !ok {
        return Err(WalletError::Policy(errors.join("; ")));
    }
    Ok(Hip23SendCheck {
        ok,
        warnings,
        errors,
    })
}

pub fn validate_type3_universal(input: &Type3CheckInput) -> Hip23SendCheck {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if input.tx_type < 3 {
        errors.push("HIP-23 patterns require transaction type >= 3".into());
    }
    if input.chain_height < ISTANBUL_HEIGHT {
        warnings.push(format!(
            "Chain height {0} is before Istanbul activation ({ISTANBUL_HEIGHT})",
            input.chain_height
        ));
    }
    if input.ast_depth > 0 && input.gas_max == 0 {
        errors.push("Type3 with AST requires gas_max > 0".into());
    }
    if input.has_asset_tex && input.gas_max == 0 {
        errors.push("Asset TEX cells require gas_max > 0".into());
    }
    if input.guard_only {
        errors.push("Guard-only topology: at least one non-guard top action required".into());
    }
    if input.action_count == 0 {
        errors.push("Transaction must contain at least one action".into());
    }

    Hip23SendCheck {
        ok: errors.is_empty(),
        warnings,
        errors,
    }
}

pub fn validate_height_scope_pattern(input: &HeightScopeInput) -> Hip23SendCheck {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if input.end != 0 && input.start > input.end {
        errors.push("HeightScope: start must be <= end when end != 0".into());
    }
    if !input.guard_before_debit {
        errors.push("P2: HeightScope must be listed before debit action".into());
    }
    if input.end == 0 {
        warnings.push("HeightScope end=0 means open-ended upper bound".into());
    }

    Hip23SendCheck {
        ok: errors.is_empty(),
        warnings,
        errors,
    }
}

pub fn validate_balance_floor_pattern(input: &BalanceFloorInput) -> Hip23SendCheck {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if !input.debit_before_floor {
        errors.push("P3: debit action(s) must be listed before BalanceFloor".into());
    }
    if input.floor_hacash_mei <= 0.0 {
        errors.push("P3: explicit non-zero HAC floor required for protection".into());
    }
    if input.floor_hacash_mei > 0.0 && input.floor_hacash_mei < 0.001 {
        warnings.push("Very small floor — confirm fee and gas are accounted for".into());
    }

    Hip23SendCheck {
        ok: errors.is_empty(),
        warnings,
        errors,
    }
}

pub fn validate_type3_readiness(gas_max: u64, has_asset_tex: bool, ast_depth: u32) -> Hip23SendCheck {
    validate_type3_universal(&Type3CheckInput {
        tx_type: 3,
        chain_height: ISTANBUL_HEIGHT,
        gas_max,
        has_asset_tex,
        ast_depth,
        guard_only: false,
        action_count: 1,
    })
}

pub fn validate_all_patterns(
    universal: &Type3CheckInput,
    p2: Option<&HeightScopeInput>,
    p3: Option<&BalanceFloorInput>,
) -> Vec<Hip23PatternCheck> {
    let mut out = vec![Hip23PatternCheck {
        pattern: "universal".into(),
        check: validate_type3_universal(universal),
    }];
    if let Some(p2) = p2 {
        out.push(Hip23PatternCheck {
            pattern: "P2".into(),
            check: validate_height_scope_pattern(p2),
        });
    }
    if let Some(p3) = p3 {
        out.push(Hip23PatternCheck {
            pattern: "P3".into(),
            check: validate_balance_floor_pattern(p3),
        });
    }
    out
}

pub fn is_valid_hacash_address(addr: &str) -> bool {
    verify_hacash_address(addr)
}

fn verify_hacash_address(addr: &str) -> bool {
    use field::Address;
    Address::from_readable(addr).is_ok()
}

/// Serialize mei for node `Amount::from` (decimal mei). Colon form is fin `value:unit` on-chain.
pub fn format_mei_for_node(amount_mei: f64) -> String {
    let rounded = (amount_mei * 1000.0).round() / 1000.0;
    let s = format!("{:.3}", rounded);
    s.trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

/// Convert wallet millis wire (`whole:frac`) to node mei decimal.
pub fn wire_mei_for_node(wire: &str) -> String {
    format_mei_for_node(parse_hacash_wire_mei(wire))
}

/// Parse HAC wire `whole:frac` (frac = millis) to mei float.
pub fn parse_hacash_wire_mei(wire: &str) -> f64 {
    let Some((whole, frac)) = wire.split_once(':') else {
        return 0.0;
    };
    let whole: f64 = whole.parse().unwrap_or(0.0);
    let frac: f64 = frac.parse().unwrap_or(0.0);
    whole + frac / 1000.0
}

pub fn validate_type4_send(
    from_kind: &str,
    to_address: &str,
    amount_mei: f64,
    balance_mei: f64,
    fee_wire: &str,
) -> WalletResult<Hip23SendCheck> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    match from_kind {
        "hybrid" => {}
        "pqckey" => {
            warnings.push(
                "PQC (v6) Type 4 uses ML-DSA only — Hybrid (v7) is recommended for secp256k1 + ML-DSA"
                    .into(),
            );
        }
        _ => {
            errors.push(
                "Type 4 send requires a PQC (v6) or Hybrid (v7) quantum account".into(),
            );
        }
    }
    if !verify_hacash_address(to_address) {
        errors.push("Invalid recipient address format".into());
    }
    if amount_mei <= 0.0 {
        errors.push("Amount must be positive".into());
    }
    let fee_mei = parse_hacash_wire_mei(fee_wire);
    if amount_mei + fee_mei > balance_mei {
        errors.push(format!(
            "Insufficient quantum balance: need {:.3} HAC (amount + fee), have {:.3}",
            amount_mei + fee_mei,
            balance_mei
        ));
    }
    if amount_mei >= 100.0 {
        warnings.push("Large Type 4 transfer — confirm WebAuthn/hardware gate if enabled".into());
    }

    Ok(Hip23SendCheck {
        ok: errors.is_empty(),
        warnings,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_address() {
        let r = validate_simple_l1_send("bad", 1.0, 10.0, 0.001);
        assert!(r.is_err());
    }

    #[test]
    fn warns_on_large_transfer() {
        let check =
            validate_simple_l1_send("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", 150.0, 200.0, 0.001).unwrap();
        assert!(check.ok);
        assert!(!check.warnings.is_empty());
    }

    #[test]
    fn type3_requires_gas_for_ast() {
        let check = validate_type3_readiness(0, false, 2);
        assert!(!check.ok);
        assert!(check.errors.iter().any(|e| e.contains("gas_max")));
    }

    #[test]
    fn p2_rejects_inverted_height_scope() {
        let check = validate_height_scope_pattern(&HeightScopeInput {
            start: 100,
            end: 50,
            guard_before_debit: true,
        });
        assert!(!check.ok);
    }

    #[test]
    fn universal_rejects_guard_only() {
        let check = validate_type3_universal(&Type3CheckInput {
            tx_type: 3,
            chain_height: ISTANBUL_HEIGHT,
            gas_max: 100,
            has_asset_tex: false,
            ast_depth: 0,
            guard_only: true,
            action_count: 1,
        });
        assert!(!check.ok);
    }

    #[test]
    fn type4_pqc_ok_with_balance_and_warning() {
        let check = validate_type4_send(
            "pqckey",
            "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            0.1,
            50.0,
            "40:244",
        )
        .unwrap();
        assert!(check.ok);
        assert!(!check.warnings.is_empty());
    }

    #[test]
    fn type4_rejects_unknown_sender_kind() {
        let check = validate_type4_send(
            "legacy",
            "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            0.1,
            50.0,
            "40:244",
        )
        .unwrap();
        assert!(!check.ok);
    }

    #[test]
    fn type4_hybrid_ok_with_balance() {
        let check = validate_type4_send(
            "hybrid",
            "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            0.1,
            50.0,
            "40:244",
        )
        .unwrap();
        assert!(check.ok);
    }

    #[test]
    fn type4_rejects_insufficient_balance() {
        let check = validate_type4_send(
            "hybrid",
            "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            1.0,
            0.5,
            "40:244",
        )
        .unwrap();
        assert!(!check.ok);
    }

    #[test]
    fn parse_hacash_wire_mei_splits_whole_frac() {
        let mei = parse_hacash_wire_mei("40:244");
        assert!((mei - 40.244).abs() < 0.001);
    }

    #[test]
    fn wire_mei_for_node_uses_decimal_mei() {
        assert_eq!(wire_mei_for_node("45:0"), "45");
        assert_eq!(wire_mei_for_node("1:244"), "1.244");
        assert_eq!(wire_mei_for_node("40:244"), "40.244");
    }
}