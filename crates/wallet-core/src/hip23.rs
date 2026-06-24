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

pub fn validate_type3_readiness(gas_max: u64, has_asset_tex: bool, ast_depth: u32) -> Hip23SendCheck {
    let warnings = Vec::new();
    let mut errors = Vec::new();

    if ast_depth > 0 && gas_max == 0 {
        errors.push("Type3 with AST requires gas_max > 0".into());
    }
    if has_asset_tex && gas_max == 0 {
        errors.push("Asset TEX cells require gas_max > 0".into());
    }

    Hip23SendCheck {
        ok: errors.is_empty(),
        warnings,
        errors,
    }
}

fn verify_hacash_address(addr: &str) -> bool {
    use field::Address;
    Address::from_readable(addr).is_ok()
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
}