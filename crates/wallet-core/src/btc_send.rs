//! On-chain BTC (satoshi) transfer on the Hacash network (action kind 8).

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::hip23::{is_valid_hacash_address, Hip23SendCheck};
use crate::l1_fee::estimate_btc_l1_fee;
use crate::node::NodeClient;

pub const BTC_TRANSFER_FEE_WIRE: &str = "1:244";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcSendPreview {
    pub from: String,
    pub to: String,
    pub satoshi: u64,
    pub btc_amount: f64,
    pub fee_mei: f64,
    pub fee_wire: String,
    pub hip23: Hip23SendCheck,
    pub summary: String,
}

pub fn btc_to_satoshi(btc: f64) -> WalletResult<u64> {
    if !btc.is_finite() || btc <= 0.0 {
        return Err(WalletError::Other("BTC amount must be positive".into()));
    }
    let sat = (btc * 100_000_000.0).round();
    if sat <= 0.0 || sat > u64::MAX as f64 {
        return Err(WalletError::Other("BTC amount out of range".into()));
    }
    Ok(sat as u64)
}

pub fn satoshi_to_btc(satoshi: u64) -> f64 {
    satoshi as f64 / 100_000_000.0
}

pub async fn preview_btc_send(
    node: &NodeClient,
    from: &str,
    to: &str,
    satoshi: u64,
) -> WalletResult<BtcSendPreview> {
    if satoshi == 0 {
        return Err(WalletError::Other("BTC amount must be greater than zero".into()));
    }
    if !is_valid_hacash_address(to) {
        return Err(WalletError::Other(
            "Invalid recipient — use a Hacash address (1…)".into(),
        ));
    }
    if from == to {
        return Err(WalletError::Other("Cannot send BTC to your own address".into()));
    }

    let balance_entry = node.query_balance_entry(from, false).await?;
    let wallet_satoshi = balance_entry.btc_satoshi();
    if wallet_satoshi < satoshi {
        return Err(WalletError::Other(format!(
            "Insufficient BTC: need {} sat, have {} sat",
            satoshi, wallet_satoshi
        )));
    }

    let hac_mei = balance_entry.hacash_mei()?;
    let fee_est = estimate_btc_l1_fee(node, from, to, satoshi).await?;
    let hip23 = validate_btc_l1_send(to, hac_mei, fee_est.fee_mei)?;
    let btc_amount = satoshi_to_btc(satoshi);

    let summary = format!(
        "Transfer {:.8} BTC ({} sat) to {}",
        btc_amount,
        satoshi,
        crate::privacy::mask_address(to)
    );

    Ok(BtcSendPreview {
        from: from.to_owned(),
        to: to.to_owned(),
        satoshi,
        btc_amount,
        fee_mei: fee_est.fee_mei,
        fee_wire: fee_est.fee_node,
        hip23,
        summary,
    })
}

fn validate_btc_l1_send(
    to_address: &str,
    hac_balance_mei: f64,
    fee_mei: f64,
) -> WalletResult<Hip23SendCheck> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if !is_valid_hacash_address(to_address) {
        errors.push("Invalid Hacash address format".into());
    }
    if fee_mei > hac_balance_mei {
        errors.push(format!(
            "Insufficient HAC for network fee: need {:.3}, have {:.3}",
            fee_mei, hac_balance_mei
        ));
    }
    warnings.push("BTC transfer on Hacash is irreversible — confirm recipient".into());

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