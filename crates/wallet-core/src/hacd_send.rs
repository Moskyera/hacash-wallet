//! On-chain HACD (diamond) transfer helpers.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::hip23::{is_valid_hacash_address, Hip23SendCheck};
use crate::l1_fee::estimate_hacd_l1_fee;
use crate::node::NodeClient;

/// Legacy minimum L1 fee wire (fallback when node is unreachable).
pub const DIAMOND_TRANSFER_FEE_WIRE: &str = "1:244";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HacdSendPreview {
    pub from: String,
    pub to: String,
    /// Primary name (first diamond) for backwards-compatible UI.
    pub diamond_name: String,
    pub diamond_names: Vec<String>,
    pub diamond_count: usize,
    pub diamond_number: Option<u64>,
    pub fee_mei: f64,
    pub fee_wire: String,
    pub hip23: Hip23SendCheck,
    pub summary: String,
}

pub fn normalize_diamond_names(raw: &[String]) -> WalletResult<Vec<String>> {
    let mut names = Vec::new();
    for item in raw {
        let n = normalize_diamond_name(item);
        if !is_valid_diamond_name(&n) {
            return Err(WalletError::Other(format!(
                "Invalid HACD name '{n}' (4–6 uppercase letters)"
            )));
        }
        if !names.contains(&n) {
            names.push(n);
        }
    }
    if names.is_empty() {
        return Err(WalletError::Other("Select at least one HACD".into()));
    }
    if names.len() > 200 {
        return Err(WalletError::Other("Maximum 200 HACD per transaction".into()));
    }
    Ok(names)
}

pub fn diamonds_readable(names: &[String]) -> String {
    names.join("")
}

pub fn normalize_diamond_name(raw: &str) -> String {
    raw.trim().to_uppercase()
}

pub fn is_valid_diamond_name(name: &str) -> bool {
    let n = normalize_diamond_name(name);
    n.len() >= 4 && n.len() <= 6 && n.chars().all(|c| c.is_ascii_uppercase())
}

pub fn parse_owned_diamonds(raw: &str) -> Vec<String> {
    let clean: String = raw.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    clean
        .as_bytes()
        .chunks(6)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .filter(|s| s.len() == 6 && is_valid_diamond_name(s))
        .collect()
}

pub async fn list_owned_diamonds(node: &NodeClient, address: &str) -> WalletResult<Vec<String>> {
    let entry = node.query_balance_entry(address, true).await?;
    Ok(entry
        .diamonds
        .map(|s| parse_owned_diamonds(&s))
        .unwrap_or_default())
}

pub async fn preview_hacd_send(
    node: &NodeClient,
    from: &str,
    to: &str,
    diamond_names: &[String],
) -> WalletResult<HacdSendPreview> {
    let names = normalize_diamond_names(diamond_names)?;
    if !is_valid_hacash_address(to) {
        return Err(WalletError::Other("Invalid recipient Hacash address".into()));
    }
    if from == to {
        return Err(WalletError::Other(
            "Cannot send HACD to your own address".into(),
        ));
    }

    let owned = list_owned_diamonds(node, from).await?;
    for name in &names {
        if !owned.iter().any(|d| d == name) {
            return Err(WalletError::Other(format!("You do not own HACD {name}")));
        }
        let info = node.query_diamond_by_name(name).await?;
        if let Some(belong) = &info.belong {
            if belong != from {
                return Err(WalletError::Other(format!(
                    "HACD {name} is not registered to your address on-chain"
                )));
            }
        }
    }

    let first_info = node.query_diamond_by_name(&names[0]).await?;
    let balance = node.balance_mei(from).await.unwrap_or(0.0);
    let fee_est = estimate_hacd_l1_fee(node, from, to, &names).await?;
    let hip23 = validate_diamond_l1_send(to, balance, fee_est.fee_mei)?;

    let summary = if names.len() == 1 {
        format!(
            "Transfer HACD {} to {}",
            names[0],
            crate::privacy::mask_address(to)
        )
    } else {
        format!(
            "Transfer {} HACD ({}{}) to {}",
            names.len(),
            names[0],
            if names.len() > 1 { "…" } else { "" },
            crate::privacy::mask_address(to)
        )
    };

    Ok(HacdSendPreview {
        from: from.to_owned(),
        to: to.to_owned(),
        diamond_name: names[0].clone(),
        diamond_names: names.clone(),
        diamond_count: names.len(),
        diamond_number: first_info.number,
        fee_mei: fee_est.fee_mei,
        fee_wire: fee_est.fee_node,
        hip23,
        summary,
    })
}

fn validate_diamond_l1_send(
    to_address: &str,
    balance_mei: f64,
    fee_mei: f64,
) -> WalletResult<Hip23SendCheck> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if !is_valid_hacash_address(to_address) {
        errors.push("Invalid Hacash address format".into());
    }
    if fee_mei > balance_mei {
        errors.push(format!(
            "Insufficient HAC for network fee: need {:.3}, have {:.3}",
            fee_mei, balance_mei
        ));
    }
    warnings.push("HACD transfer is irreversible — confirm recipient address".into());

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

#[cfg(test)]
mod tests {
    use super::parse_owned_diamonds;

    #[test]
    fn parse_owned_diamonds_splits_six_letter_names() {
        let raw = "ZAKXMIWTYUIA";
        let list = parse_owned_diamonds(raw);
        assert_eq!(list, vec!["ZAKXMI".to_string(), "WTYUIA".to_string()]);
    }
}