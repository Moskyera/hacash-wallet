//! On-chain HIP-20/native-asset transfers (action kind 17).
//!
//! Asset serials and amounts stay as exact `u64` decimal strings at the UI
//! boundary so JavaScript cannot silently round values above 2^53.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::hip23::{Hip23SendCheck, is_valid_hacash_address};
use crate::l1_fee::estimate_native_asset_l1_fee;
use crate::node::NodeClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeAssetSendPreview {
    pub from: String,
    pub to: String,
    pub serial: String,
    pub amount: String,
    pub owned_amount: String,
    pub fee_mei: f64,
    pub fee_wire: String,
    pub hip23: Hip23SendCheck,
    pub summary: String,
}

pub fn parse_positive_u64_decimal(raw: &str, label: &str) -> WalletResult<u64> {
    let value = raw.trim();
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(WalletError::Other(format!(
            "{label} must be a canonical positive integer"
        )));
    }
    value
        .parse::<u64>()
        .map_err(|_| WalletError::Other(format!("{label} is out of range")))
}

pub async fn preview_native_asset_send(
    node: &NodeClient,
    from: &str,
    to: &str,
    serial_raw: &str,
    amount_raw: &str,
) -> WalletResult<NativeAssetSendPreview> {
    if !is_valid_hacash_address(to) {
        return Err(WalletError::Other(
            "Invalid recipient. Use a Hacash address".into(),
        ));
    }
    if from == to {
        return Err(WalletError::Other(
            "Cannot send a native asset to your own address".into(),
        ));
    }
    let serial = parse_positive_u64_decimal(serial_raw, "Asset serial")?;
    let amount = parse_positive_u64_decimal(amount_raw, "Asset amount")?;

    let balance = node.query_balance_entry(from, true).await?;
    let owned_amount = balance
        .native_assets()?
        .into_iter()
        .find(|asset| asset.serial == serial)
        .map(|asset| asset.amount)
        .unwrap_or(0);
    if owned_amount < amount {
        return Err(WalletError::Other(format!(
            "Insufficient HIP-20 asset #{serial}: need {amount}, have {owned_amount}"
        )));
    }

    let fee = estimate_native_asset_l1_fee(
        node,
        from,
        to,
        serial,
        amount,
        crate::send_options::L1FeeSpeed::Normal,
    )
    .await?;
    let hac_balance = balance.hacash_mei()?;
    let mut errors = Vec::new();
    if fee.fee_mei > hac_balance {
        errors.push(format!(
            "Insufficient HAC for network fee: need {:.6}, have {:.6}",
            fee.fee_mei, hac_balance
        ));
    }
    if !errors.is_empty() {
        return Err(WalletError::Policy(errors.join("; ")));
    }
    let hip23 = Hip23SendCheck {
        ok: true,
        warnings: vec![
            "HIP-20 transfers are irreversible. Verify the asset serial and recipient.".into(),
        ],
        errors,
    };
    let summary = format!(
        "Transfer {amount} units of HIP-20 asset #{serial} to {}",
        crate::privacy::mask_address(to)
    );

    Ok(NativeAssetSendPreview {
        from: from.to_owned(),
        to: to.to_owned(),
        serial: serial.to_string(),
        amount: amount.to_string(),
        owned_amount: owned_amount.to_string(),
        fee_mei: fee.fee_mei,
        fee_wire: fee.fee_node,
        hip23,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_u64_parser_rejects_ambiguous_or_unsafe_values() {
        for value in ["", "0", "01", "-1", "1.0", "1e3"] {
            assert!(
                parse_positive_u64_decimal(value, "amount").is_err(),
                "{value}"
            );
        }
        assert_eq!(parse_positive_u64_decimal(" 1 ", "amount").unwrap(), 1);
        assert_eq!(
            parse_positive_u64_decimal("18446744073709551615", "amount").unwrap(),
            u64::MAX
        );
        assert!(parse_positive_u64_decimal("18446744073709551616", "amount").is_err());
    }
}
