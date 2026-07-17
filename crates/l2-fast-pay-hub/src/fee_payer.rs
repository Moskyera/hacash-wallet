use crate::error::{HubError, HubResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubFeePayer {
    Sender,
    Recipient,
}

pub fn parse_fee_payer(raw: Option<&str>) -> HubResult<HubFeePayer> {
    match raw.unwrap_or("sender").trim().to_lowercase().as_str() {
        "sender" | "" => Ok(HubFeePayer::Sender),
        "recipient" | "payee" => Ok(HubFeePayer::Recipient),
        other => Err(HubError::Payment(format!("unknown fee_payer: {other}"))),
    }
}
