//! Air-gapped QR transfer protocol for L1 sends.
//!
//! Online coordinator builds an unsigned tx and encodes it as one or more QR strings.
//! Offline signer scans, signs locally, and shows signed QR(s) for broadcast.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

pub const AIRGAP_PREFIX: &str = "hacash-airgap:";
pub const AIRGAP_VERSION: u32 = 1;
/// Conservative chunk size for high-capacity QR (alphanumeric mode).
const CHUNK_PAYLOAD_MAX: usize = 1400;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AirgapEnvelope {
    Unsigned(AirgapUnsigned),
    Signed(AirgapSigned),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AirgapUnsigned {
    pub v: u32,
    pub from: String,
    pub to: String,
    pub amount_mei: f64,
    pub amount_wire: String,
    pub fee: String,
    pub body_hex: String,
    pub summary: String,
    /// `1` = legacy L1, `4` = quantum Type 4 (default `1` for older QRs).
    #[serde(default = "default_airgap_tx_type")]
    pub tx_type: u8,
}

fn default_airgap_tx_type() -> u8 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AirgapSigned {
    pub v: u32,
    pub from: String,
    pub to: String,
    pub amount_mei: f64,
    pub signed_hex: String,
    pub summary: String,
    #[serde(default = "default_airgap_tx_type")]
    pub tx_type: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct AirgapPrepareResult {
    pub envelope: AirgapUnsigned,
    pub qr_parts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AirgapSignResult {
    pub envelope: AirgapSigned,
    pub qr_parts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AirgapParseResult {
    pub envelope: Option<AirgapEnvelope>,
    pub needs_more_parts: bool,
    pub received_parts: usize,
    pub total_parts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrFragment {
    Single(String),
    Chunk { index: usize, total: usize, payload: String },
}

pub fn encode_envelope_qr(envelope: &AirgapEnvelope) -> WalletResult<Vec<String>> {
    validate_envelope(envelope)?;
    let json = serde_json::to_string(envelope)
        .map_err(|e| WalletError::Transaction(format!("airgap encode: {e}")))?;
    Ok(chunk_payload(&json))
}

pub fn parse_qr_fragment(text: &str) -> WalletResult<QrFragment> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(WalletError::Transaction("empty QR payload".into()));
    }
    if trimmed.starts_with(AIRGAP_PREFIX) {
        let rest = trimmed
            .strip_prefix(AIRGAP_PREFIX)
            .ok_or_else(|| WalletError::Transaction("invalid airgap prefix".into()))?;
        let (header, payload) = rest
            .split_once(':')
            .ok_or_else(|| WalletError::Transaction("airgap chunk missing payload".into()))?;
        let (index_s, total_s) = header
            .split_once('/')
            .ok_or_else(|| WalletError::Transaction("airgap chunk header malformed".into()))?;
        let index: usize = index_s
            .parse()
            .map_err(|_| WalletError::Transaction("airgap chunk index invalid".into()))?;
        let total: usize = total_s
            .parse()
            .map_err(|_| WalletError::Transaction("airgap chunk total invalid".into()))?;
        if index == 0 || total == 0 || index > total {
            return Err(WalletError::Transaction(
                "airgap chunk index out of range".into(),
            ));
        }
        if total > 64 {
            return Err(WalletError::Transaction("airgap too many chunks".into()));
        }
        return Ok(QrFragment::Chunk {
            index,
            total,
            payload: payload.to_owned(),
        });
    }
    if trimmed.starts_with('{') {
        return Ok(QrFragment::Single(trimmed.to_owned()));
    }
    Err(WalletError::Transaction(
        "unrecognized airgap QR format".into(),
    ))
}

pub fn reassemble_chunks(parts: &[String]) -> WalletResult<String> {
    if parts.is_empty() {
        return Err(WalletError::Transaction("no QR parts to reassemble".into()));
    }
    if parts.len() == 1 {
        return Ok(parts[0].clone());
    }
    let mut fragments: Vec<(usize, usize, String)> = Vec::with_capacity(parts.len());
    let mut expected_total: Option<usize> = None;
    for part in parts {
        match parse_qr_fragment(part)? {
            QrFragment::Single(payload) => return Ok(payload),
            QrFragment::Chunk {
                index,
                total,
                payload,
            } => {
                if let Some(exp) = expected_total {
                    if exp != total {
                        return Err(WalletError::Transaction(
                            "airgap chunk totals disagree".into(),
                        ));
                    }
                } else {
                    expected_total = Some(total);
                }
                fragments.push((index, total, payload));
            }
        }
    }
    let total = expected_total.ok_or_else(|| {
        WalletError::Transaction("airgap reassembly missing chunk metadata".into())
    })?;
    if fragments.len() != total {
        return Err(WalletError::Transaction(format!(
            "airgap needs {total} chunks, got {}",
            fragments.len()
        )));
    }
    fragments.sort_by_key(|(i, _, _)| *i);
    for (i, (index, _, _)) in fragments.iter().enumerate() {
        if *index != i + 1 {
            return Err(WalletError::Transaction(format!(
                "airgap missing chunk {}",
                i + 1
            )));
        }
    }
    Ok(fragments.into_iter().map(|(_, _, p)| p).collect())
}

pub fn decode_envelope_json(json: &str) -> WalletResult<AirgapEnvelope> {
    let envelope: AirgapEnvelope = serde_json::from_str(json)
        .map_err(|e| WalletError::Transaction(format!("airgap json invalid: {e}")))?;
    validate_envelope(&envelope)?;
    Ok(envelope)
}

pub fn parse_airgap_qr_parts(parts: &[String]) -> WalletResult<AirgapParseResult> {
    if parts.is_empty() {
        return Err(WalletError::Transaction("no QR input".into()));
    }
    if parts.len() == 1 {
        return parse_airgap_qr_text(&parts[0]);
    }
    let mut chunk_meta: Vec<(usize, usize)> = Vec::new();
    for part in parts {
        if let QrFragment::Chunk { index, total, .. } = parse_qr_fragment(part)? {
            chunk_meta.push((index, total));
        } else {
            return parse_airgap_qr_text(part);
        }
    }
    let total = chunk_meta.first().map(|(_, t)| *t).unwrap_or(0);
    let received = parts.len();
    if received < total {
        return Ok(AirgapParseResult {
            envelope: None,
            needs_more_parts: true,
            received_parts: received,
            total_parts: total,
        });
    }
    let json = reassemble_chunks(parts)?;
    let envelope = decode_envelope_json(&json)?;
    Ok(AirgapParseResult {
        envelope: Some(envelope),
        needs_more_parts: false,
        received_parts: received,
        total_parts: total,
    })
}

pub fn parse_airgap_qr_text(text: &str) -> WalletResult<AirgapParseResult> {
    match parse_qr_fragment(text)? {
        QrFragment::Single(json) => {
            let envelope = decode_envelope_json(&json)?;
            Ok(AirgapParseResult {
                envelope: Some(envelope),
                needs_more_parts: false,
                received_parts: 1,
                total_parts: 1,
            })
        }
        QrFragment::Chunk { index, total, .. } => Ok(AirgapParseResult {
            envelope: None,
            needs_more_parts: true,
            received_parts: 1,
            total_parts: total.max(index),
        }),
    }
}

fn chunk_payload(json: &str) -> Vec<String> {
    if json.len() <= CHUNK_PAYLOAD_MAX {
        return vec![json.to_owned()];
    }
    let chunks: Vec<&str> = json
        .as_bytes()
        .chunks(CHUNK_PAYLOAD_MAX)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    let total = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, payload)| format!("{AIRGAP_PREFIX}{}/{total}:{payload}", i + 1))
        .collect()
}

fn validate_envelope(envelope: &AirgapEnvelope) -> WalletResult<()> {
    match envelope {
        AirgapEnvelope::Unsigned(u) => {
            if u.v != AIRGAP_VERSION {
                return Err(WalletError::Transaction(format!(
                    "unsupported airgap version {}",
                    u.v
                )));
            }
            if u.from.is_empty() || u.to.is_empty() {
                return Err(WalletError::Transaction(
                    "airgap unsigned missing addresses".into(),
                ));
            }
            if u.body_hex.is_empty() {
                return Err(WalletError::Transaction(
                    "airgap unsigned missing body_hex".into(),
                ));
            }
            hex::decode(&u.body_hex)
                .map_err(|e| WalletError::Transaction(format!("invalid body_hex: {e}")))?;
            Ok(())
        }
        AirgapEnvelope::Signed(s) => {
            if s.v != AIRGAP_VERSION {
                return Err(WalletError::Transaction(format!(
                    "unsupported airgap version {}",
                    s.v
                )));
            }
            if s.from.is_empty() || s.to.is_empty() {
                return Err(WalletError::Transaction(
                    "airgap signed missing addresses".into(),
                ));
            }
            if s.signed_hex.is_empty() {
                return Err(WalletError::Transaction(
                    "airgap signed missing signed_hex".into(),
                ));
            }
            hex::decode(&s.signed_hex)
                .map_err(|e| WalletError::Transaction(format!("invalid signed_hex: {e}")))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unsigned() -> AirgapUnsigned {
        AirgapUnsigned {
            v: AIRGAP_VERSION,
            from: "1From".into(),
            to: "1To".into(),
            amount_mei: 1.5,
            amount_wire: "1:500".into(),
            fee: "1:244".into(),
            body_hex: "010203".into(),
            summary: "test send".into(),
            tx_type: 1,
        }
    }

    #[test]
    fn roundtrip_single_qr() {
        let env = AirgapEnvelope::Unsigned(sample_unsigned());
        let parts = encode_envelope_qr(&env).unwrap();
        assert_eq!(parts.len(), 1);
        let parsed = parse_airgap_qr_text(&parts[0]).unwrap();
        assert!(!parsed.needs_more_parts);
        assert_eq!(parsed.envelope.as_ref(), Some(&env));
    }

    #[test]
    fn chunked_reassembly() {
        let big_body = "ab".repeat(2000);
        let env = AirgapEnvelope::Unsigned(AirgapUnsigned {
            body_hex: big_body,
            ..sample_unsigned()
        });
        let parts = encode_envelope_qr(&env).unwrap();
        assert!(parts.len() > 1);
        let parsed = parse_airgap_qr_parts(&parts).unwrap();
        assert_eq!(parsed.envelope.as_ref(), Some(&env));
    }

    #[test]
    fn rejects_malformed_chunk_header() {
        assert!(parse_qr_fragment("hacash-airgap:0/2:xx").is_err());
        assert!(parse_qr_fragment("hacash-airgap:2/1:xx").is_err());
    }

    #[test]
    fn type4_signed_envelope_requires_addresses() {
        let valid = AirgapEnvelope::Signed(AirgapSigned {
            v: AIRGAP_VERSION,
            from: "3Sender".into(),
            to: "1Recipient".into(),
            amount_mei: 0.1,
            signed_hex: "010203".into(),
            summary: "type 4".into(),
            tx_type: 4,
        });
        assert!(encode_envelope_qr(&valid).is_ok());

        let missing_to = AirgapEnvelope::Signed(AirgapSigned {
            v: AIRGAP_VERSION,
            from: "3Sender".into(),
            to: String::new(),
            amount_mei: 0.1,
            signed_hex: "010203".into(),
            summary: "type 4".into(),
            tx_type: 4,
        });
        assert!(encode_envelope_qr(&missing_to).is_err());
    }
}