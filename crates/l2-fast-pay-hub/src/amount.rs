use crate::error::{HubError, HubResult};

/// Parse HAC amount from node wire (`whole:frac` millis) or plain decimal mei.
pub fn parse_amount_mei(wire: &str) -> HubResult<f64> {
    let s = wire.trim();
    if s.is_empty() {
        return Err(HubError::Payment("empty amount".into()));
    }
    if let Some((whole, frac)) = s.split_once(':') {
        let whole: u64 = whole
            .parse()
            .map_err(|_| HubError::Payment(format!("invalid amount whole: {wire}")))?;
        let frac: u16 = frac
            .parse()
            .map_err(|_| HubError::Payment(format!("invalid amount frac: {wire}")))?;
        if frac > 999 {
            return Err(HubError::Payment(format!(
                "amount fraction exceeds millimeis: {wire}"
            )));
        }
        return Ok(whole as f64 + frac as f64 / 1000.0);
    }
    let amount = s
        .parse::<f64>()
        .map_err(|_| HubError::Payment(format!("invalid amount: {wire}")))?;
    if !amount.is_finite() || amount < 0.0 {
        return Err(HubError::Payment(format!(
            "amount must be finite and non-negative: {wire}"
        )));
    }
    let millis = amount * 1000.0;
    let rounded = millis.round();
    if !millis.is_finite() || (millis - rounded).abs() > 1e-9 {
        return Err(HubError::Payment(format!(
            "amount must use whole millimeis: {wire}"
        )));
    }
    Ok(rounded / 1000.0)
}

pub fn format_amount_mei(amount_mei: f64) -> String {
    let rounded = (amount_mei * 1000.0).round() / 1000.0;
    let s = format!("{rounded:.3}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_wire() {
        assert!((parse_amount_mei("1:244").unwrap() - 1.244).abs() < 1e-9);
    }

    #[test]
    fn parses_decimal() {
        assert!((parse_amount_mei("10.5").unwrap() - 10.5).abs() < 1e-9);
    }

    #[test]
    fn rejects_sub_millimei_precision() {
        assert!(parse_amount_mei("1.0004").is_err());
    }

    #[test]
    fn rejects_non_canonical_or_non_finite_values() {
        assert!(parse_amount_mei("1:1000").is_err());
        assert!(parse_amount_mei("NaN").is_err());
        assert!(parse_amount_mei("-1").is_err());
    }
}
