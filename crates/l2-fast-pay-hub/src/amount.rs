use crate::error::{HubError, HubResult};

/// Parse HAC amount from node wire (`whole:frac` millis) or plain decimal mei.
pub fn parse_amount_mei(wire: &str) -> HubResult<f64> {
    let s = wire.trim();
    if s.is_empty() {
        return Err(HubError::Payment("empty amount".into()));
    }
    if let Some((whole, frac)) = s.split_once(':') {
        let whole: f64 = whole
            .parse()
            .map_err(|_| HubError::Payment(format!("invalid amount whole: {wire}")))?;
        let frac: f64 = frac
            .parse()
            .map_err(|_| HubError::Payment(format!("invalid amount frac: {wire}")))?;
        return Ok(whole + frac / 1000.0);
    }
    s.parse::<f64>()
        .map_err(|_| HubError::Payment(format!("invalid amount: {wire}")))
}

pub fn format_amount_mei(amount_mei: f64) -> String {
    let rounded = (amount_mei * 1000.0).round() / 1000.0;
    let s = format!("{rounded:.3}");
    s.trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
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
}