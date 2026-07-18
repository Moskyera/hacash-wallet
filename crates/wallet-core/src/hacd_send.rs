//! On-chain HACD (diamond) transfer helpers.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::hip23::{Hip23SendCheck, is_valid_hacash_address};
use crate::l1_fee::estimate_hacd_l1_fee;
use crate::node::NodeClient;
use crate::send_options::{HACD_SERVICE_FEE_MEI, WALLET_TREASURY_ADDRESS};

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
    pub service_fee_mei: f64,
    pub service_fee_treasury: String,
    pub total_hac_debit_mei: f64,
    pub hip23: Hip23SendCheck,
    pub summary: String,
}

pub fn normalize_diamond_names(raw: &[String]) -> WalletResult<Vec<String>> {
    let mut names = Vec::new();
    for item in raw {
        let n = normalize_diamond_name(item);
        if !is_valid_diamond_name(&n) {
            return Err(WalletError::Other(format!(
                "Invalid HACD name '{n}' (4 to 6 uppercase letters)"
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
        return Err(WalletError::Other(
            "Maximum 200 HACD per transaction".into(),
        ));
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
    const ALPHABET: &str = "WTYUIAHXVMEKBSZN";
    let normalized = normalize_diamond_name(name);
    (4..=6).contains(&normalized.len())
        && normalized
            .chars()
            .all(|character| ALPHABET.contains(character))
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
        .as_deref()
        .map(parse_owned_diamonds)
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
        return Err(WalletError::Other(
            "Invalid recipient Hacash address".into(),
        ));
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
        if let Some(belong) = &info.belong
            && belong != from
        {
            return Err(WalletError::Other(format!(
                "HACD {name} is not registered to your address on-chain"
            )));
        }
    }

    let first_info = node.query_diamond_by_name(&names[0]).await?;
    let balance = node.balance_mei(from).await?;
    let fee_est = estimate_hacd_l1_fee(
        node,
        from,
        to,
        &names,
        crate::send_options::L1FeeSpeed::Normal,
    )
    .await?;
    let total_hac_debit_mei = fee_est.fee_mei + HACD_SERVICE_FEE_MEI;
    let hip23 = validate_diamond_l1_send(to, balance, total_hac_debit_mei)?;

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
        service_fee_mei: HACD_SERVICE_FEE_MEI,
        service_fee_treasury: WALLET_TREASURY_ADDRESS.into(),
        total_hac_debit_mei,
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
    warnings.push("HACD transfer is irreversible. confirm recipient address".into());

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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::json;

    use super::{is_valid_diamond_name, list_owned_diamonds, parse_owned_diamonds};
    use crate::node::NodeClient;

    #[test]
    fn parse_owned_diamonds_splits_six_letter_names() {
        let raw = "ZAKXMIWTYUIA";
        let list = parse_owned_diamonds(raw);
        assert_eq!(list, vec!["ZAKXMI".to_string(), "WTYUIA".to_string()]);
    }

    #[test]
    fn diamond_names_use_the_official_alphabet() {
        assert!(is_valid_diamond_name("vwmmmm"));
        assert!(is_valid_diamond_name("WTYU"));
        assert!(!is_valid_diamond_name("ABCDEF"));
        assert!(!is_valid_diamond_name("WTYC"));
    }

    #[tokio::test]
    async fn owned_listing_uses_one_balance_call_and_no_metadata_calls() {
        let balance_calls = Arc::new(AtomicUsize::new(0));
        let diamond_calls = Arc::new(AtomicUsize::new(0));
        let route_balance_calls = Arc::clone(&balance_calls);
        let route_diamond_calls = Arc::clone(&diamond_calls);
        let app = Router::new()
            .route(
                "/query/balance",
                get(move || {
                    let calls = Arc::clone(&route_balance_calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Json(json!({
                            "ret": 0,
                            "list": [{
                                "address": "1Example",
                                "hacash": "12.5",
                                "diamond": 2,
                                "satoshi": 42,
                                "diamonds": "ZAKXMIWTYUIA"
                            }]
                        }))
                    }
                }),
            )
            .route(
                "/query/diamond",
                get(move || {
                    let calls = Arc::clone(&route_diamond_calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Json(json!({ "ret": 1, "err": "metadata must not be queried" }))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock node");
        let address = listener.local_addr().expect("mock node address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock node");
        });
        let node = NodeClient::new(format!("http://{address}")).expect("mock node client");

        let names = list_owned_diamonds(&node, "1Example")
            .await
            .expect("owned HACD list");

        assert_eq!(names, vec!["ZAKXMI".to_string(), "WTYUIA".to_string()]);
        assert_eq!(balance_calls.load(Ordering::SeqCst), 1);
        assert_eq!(diamond_calls.load(Ordering::SeqCst), 0);
        server.abort();
    }
}
