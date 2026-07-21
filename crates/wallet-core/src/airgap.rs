//! Air-gapped QR transfer protocol for L1 sends.
//!
//! Online coordinator builds an unsigned tx and encodes it as one or more QR strings.
//! Offline signer scans, signs locally, and shows signed QR(s) for broadcast.

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

pub const AIRGAP_PREFIX: &str = "hacash-airgap:";
pub const AIRGAP_VERSION: u32 = 1;
/// Airgap v1 originally used `1` as a wallet-local label for classic L1 even
/// though the node builds a consensus Type 2 transaction. New envelopes store
/// the consensus type, while this alias remains accepted for existing QR data.
pub const AIRGAP_V1_LEGACY_L1_ALIAS: u8 = 1;
pub const AIRGAP_CLASSIC_L1_TX_TYPE: u8 = 2;
/// Conservative chunk size for high-capacity QR (alphanumeric mode).
const CHUNK_PAYLOAD_MAX: usize = 1400;
const AIRGAP_MAX_CHUNKS: usize = 64;
const AIRGAP_MAX_JSON_BYTES: usize = AIRGAP_MAX_CHUNKS * CHUNK_PAYLOAD_MAX;

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
    #[serde(default)]
    pub service_fee_mei: f64,
    #[serde(default)]
    pub service_fee_treasury: Option<String>,
    pub body_hex: String,
    pub summary: String,
    /// Consensus transaction type. Airgap v1 also accepts the historical
    /// wallet-local value `1` as an alias for classic consensus Type 2.
    #[serde(default = "default_airgap_tx_type")]
    pub tx_type: u8,
}

fn default_airgap_tx_type() -> u8 {
    AIRGAP_V1_LEGACY_L1_ALIAS
}

/// Resolve the transaction type represented by an airgap envelope.
///
/// Version 1 predates consensus Type 3 support and can carry only a classic
/// Type 2 transaction or a testnet-only Type 4 transaction. The old value `1`
/// is retained solely as a compatibility alias for already exported QR data.
pub fn canonical_airgap_tx_type(version: u32, tx_type: u8) -> WalletResult<u8> {
    if version != AIRGAP_VERSION {
        return Err(WalletError::Transaction(format!(
            "unsupported airgap version {version}"
        )));
    }
    match tx_type {
        AIRGAP_V1_LEGACY_L1_ALIAS => Ok(AIRGAP_CLASSIC_L1_TX_TYPE),
        AIRGAP_CLASSIC_L1_TX_TYPE | 4 => Ok(tx_type),
        _ => Err(WalletError::Transaction(format!(
            "airgap version {version} does not support consensus transaction type {tx_type}"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalAirgapAmount {
    pub amount_mei: f64,
    pub amount_wire: String,
}

/// Convert the compatibility `f64` amount into the exact decimal value that is
/// put in the transaction body. Air-gap metadata must carry this value, not the
/// caller's potentially higher precision input.
pub(crate) fn canonicalize_airgap_amount(amount_mei: f64) -> WalletResult<CanonicalAirgapAmount> {
    crate::hip23::validate_hac_amount_mei(amount_mei)?;
    let amount_wire = crate::hip23::format_mei_for_node(amount_mei);
    let amount_mei = amount_wire.parse::<f64>().map_err(|_| {
        WalletError::Transaction("canonical air-gap amount is not a decimal number".into())
    })?;
    crate::hip23::validate_hac_amount_mei(amount_mei)?;
    Ok(CanonicalAirgapAmount {
        amount_mei,
        amount_wire,
    })
}

/// Bind the human-readable amount to the exact amount used when reconstructing
/// the transfer action. Exact string and floating-point checks intentionally
/// reject alternate encodings so UI, policy, wallet fee and body cannot diverge.
pub(crate) fn validate_airgap_amount_binding(
    amount_mei: f64,
    amount_wire: &str,
) -> WalletResult<CanonicalAirgapAmount> {
    let canonical = canonicalize_airgap_amount(amount_mei)?;
    let parsed_wire = amount_wire.parse::<f64>().map_err(|_| {
        WalletError::Policy("air-gap amount_wire is not a canonical decimal amount".into())
    })?;
    if amount_wire != canonical.amount_wire
        || parsed_wire.to_bits() != canonical.amount_mei.to_bits()
        || amount_mei.to_bits() != canonical.amount_mei.to_bits()
    {
        return Err(WalletError::Policy(
            "air-gap amount metadata does not match the canonical transfer amount".into(),
        ));
    }
    Ok(canonical)
}

pub(crate) fn canonical_airgap_summary(
    tx_type: u8,
    to: &str,
    amount_wire: &str,
) -> WalletResult<String> {
    match tx_type {
        AIRGAP_CLASSIC_L1_TX_TYPE => Ok(format!("Send {amount_wire} HAC to {to}")),
        4 => Ok(format!(
            "Send {amount_wire} HAC to {to} (Type 4 testnet lab)"
        )),
        _ => Err(WalletError::Policy(format!(
            "unsupported air-gap transaction type {tx_type}"
        ))),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AirgapSigned {
    pub v: u32,
    pub from: String,
    pub to: String,
    pub amount_mei: f64,
    #[serde(default)]
    pub amount_wire: String,
    #[serde(default)]
    pub fee: String,
    #[serde(default)]
    pub service_fee_mei: f64,
    #[serde(default)]
    pub service_fee_treasury: Option<String>,
    pub signed_hex: String,
    pub summary: String,
    #[serde(default = "default_airgap_tx_type")]
    pub tx_type: u8,
}

/// Canonical, body-bound facts safe for display before signing or broadcast.
/// The envelope's free-form summary is deliberately not exposed.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AirgapInspection {
    pub kind: String,
    pub tx_type: u8,
    pub network_mode: String,
    pub from: String,
    pub to: String,
    pub amount_mei: f64,
    pub amount_wire: String,
    pub network_fee: String,
    pub wallet_fee_mei: f64,
    pub wallet_fee_wire: String,
    pub wallet_fee_treasury: String,
    pub body_sha256: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AirgapPrepareResult {
    pub envelope: AirgapUnsigned,
    pub inspection: AirgapInspection,
    pub qr_parts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AirgapSignResult {
    pub envelope: AirgapSigned,
    pub inspection: AirgapInspection,
    pub qr_parts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AirgapParseResult {
    pub envelope: Option<AirgapEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inspection: Option<AirgapInspection>,
    pub needs_more_parts: bool,
    pub received_parts: usize,
    pub total_parts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrFragment {
    Single(String),
    Chunk {
        index: usize,
        total: usize,
        payload: String,
    },
}

pub fn encode_envelope_qr(envelope: &AirgapEnvelope) -> WalletResult<Vec<String>> {
    validate_envelope(envelope)?;
    let json = serde_json::to_string(envelope)
        .map_err(|e| WalletError::Transaction(format!("airgap encode: {e}")))?;
    if json.len() > AIRGAP_MAX_JSON_BYTES {
        return Err(WalletError::Transaction(format!(
            "airgap payload exceeds {AIRGAP_MAX_JSON_BYTES} byte limit"
        )));
    }
    let parts = chunk_payload(&json);
    if parts.len() > AIRGAP_MAX_CHUNKS {
        return Err(WalletError::Transaction(format!(
            "airgap payload requires more than {AIRGAP_MAX_CHUNKS} QR chunks"
        )));
    }
    Ok(parts)
}

pub fn parse_qr_fragment(text: &str) -> WalletResult<QrFragment> {
    if text.len() > AIRGAP_MAX_JSON_BYTES {
        return Err(WalletError::Transaction(format!(
            "airgap payload exceeds {AIRGAP_MAX_JSON_BYTES} byte limit"
        )));
    }
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
        if total > AIRGAP_MAX_CHUNKS {
            return Err(WalletError::Transaction("airgap too many chunks".into()));
        }
        if payload.len() > CHUNK_PAYLOAD_MAX {
            return Err(WalletError::Transaction(format!(
                "airgap chunk payload exceeds {CHUNK_PAYLOAD_MAX} byte limit"
            )));
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
    if parts.len() > AIRGAP_MAX_CHUNKS {
        return Err(WalletError::Transaction("airgap too many chunks".into()));
    }
    let mut fragments: Vec<(usize, usize, String)> = Vec::with_capacity(parts.len());
    let mut expected_total: Option<usize> = None;
    let mut total_payload_bytes = 0usize;
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
                total_payload_bytes =
                    total_payload_bytes
                        .checked_add(payload.len())
                        .ok_or_else(|| {
                            WalletError::Transaction("airgap payload size overflow".into())
                        })?;
                if total_payload_bytes > AIRGAP_MAX_JSON_BYTES {
                    return Err(WalletError::Transaction(format!(
                        "airgap payload exceeds {AIRGAP_MAX_JSON_BYTES} byte limit"
                    )));
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
    if json.len() > AIRGAP_MAX_JSON_BYTES {
        return Err(WalletError::Transaction(format!(
            "airgap payload exceeds {AIRGAP_MAX_JSON_BYTES} byte limit"
        )));
    }
    let envelope: AirgapEnvelope = serde_json::from_str(json)
        .map_err(|e| WalletError::Transaction(format!("airgap json invalid: {e}")))?;
    validate_envelope(&envelope)?;
    Ok(envelope)
}

pub fn parse_airgap_qr_parts(parts: &[String]) -> WalletResult<AirgapParseResult> {
    if parts.len() > AIRGAP_MAX_CHUNKS {
        return Err(WalletError::Transaction("airgap too many chunks".into()));
    }
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
            inspection: None,
            needs_more_parts: true,
            received_parts: received,
            total_parts: total,
        });
    }
    let json = reassemble_chunks(parts)?;
    let envelope = decode_envelope_json(&json)?;
    Ok(AirgapParseResult {
        envelope: Some(envelope),
        inspection: None,
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
                inspection: None,
                needs_more_parts: false,
                received_parts: 1,
                total_parts: 1,
            })
        }
        QrFragment::Chunk { index, total, .. } => Ok(AirgapParseResult {
            envelope: None,
            inspection: None,
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

    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < json.len() {
        let mut end = (start + CHUNK_PAYLOAD_MAX).min(json.len());
        while !json.is_char_boundary(end) {
            end -= 1;
        }
        debug_assert!(end > start);
        chunks.push(&json[start..end]);
        start = end;
    }

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
            canonical_airgap_tx_type(u.v, u.tx_type)?;
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
            canonical_airgap_tx_type(s.v, s.tx_type)?;
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
            amount_wire: "1.5".into(),
            fee: "1:244".into(),
            service_fee_mei: 0.0045,
            service_fee_treasury: Some(crate::send_options::WALLET_TREASURY_ADDRESS.into()),
            body_hex: "010203".into(),
            summary: "Send 1.5 HAC to 1To".into(),
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
            amount_wire: "0.1".into(),
            fee: "1:244".into(),
            service_fee_mei: 0.0003,
            service_fee_treasury: Some(crate::send_options::WALLET_TREASURY_ADDRESS.into()),
            signed_hex: "010203".into(),
            summary: "Send 0.1 HAC to 1Recipient (Type 4 testnet lab)".into(),
            tx_type: 4,
        });
        assert!(encode_envelope_qr(&valid).is_ok());

        let missing_to = AirgapEnvelope::Signed(AirgapSigned {
            v: AIRGAP_VERSION,
            from: "3Sender".into(),
            to: String::new(),
            amount_mei: 0.1,
            amount_wire: "0.1".into(),
            fee: "1:244".into(),
            service_fee_mei: 0.0003,
            service_fee_treasury: Some(crate::send_options::WALLET_TREASURY_ADDRESS.into()),
            signed_hex: "010203".into(),
            summary: "Send 0.1 HAC to  (Type 4 testnet lab)".into(),
            tx_type: 4,
        });
        assert!(encode_envelope_qr(&missing_to).is_err());
    }

    #[test]
    fn unicode_chunking_preserves_every_byte_across_a_boundary() {
        let payload = format!("{}€tail", "a".repeat(CHUNK_PAYLOAD_MAX - 1));
        let chunks = chunk_payload(&payload);
        assert_eq!(chunks.len(), 2);
        assert_eq!(reassemble_chunks(&chunks).unwrap(), payload);
        for chunk in chunks {
            let QrFragment::Chunk { payload, .. } = parse_qr_fragment(&chunk).unwrap() else {
                panic!("multi-part payload must use chunk framing");
            };
            assert!(payload.len() <= CHUNK_PAYLOAD_MAX);
        }
    }

    #[test]
    fn payload_limits_accept_boundaries_and_reject_one_byte_over() {
        let chunk_at_limit = format!("{AIRGAP_PREFIX}1/1:{}", "a".repeat(CHUNK_PAYLOAD_MAX));
        assert!(parse_qr_fragment(&chunk_at_limit).is_ok());
        let chunk_over_limit = format!("{AIRGAP_PREFIX}1/1:{}", "a".repeat(CHUNK_PAYLOAD_MAX + 1));
        assert!(
            parse_qr_fragment(&chunk_over_limit)
                .unwrap_err()
                .to_string()
                .contains("chunk payload exceeds")
        );

        let single_at_limit = format!("{{{}", "a".repeat(AIRGAP_MAX_JSON_BYTES - 1));
        assert!(matches!(
            parse_qr_fragment(&single_at_limit).unwrap(),
            QrFragment::Single(_)
        ));
        let single_over_limit = format!("{{{}", "a".repeat(AIRGAP_MAX_JSON_BYTES));
        assert!(
            parse_qr_fragment(&single_over_limit)
                .unwrap_err()
                .to_string()
                .contains("payload exceeds")
        );
        assert!(
            decode_envelope_json(&single_over_limit)
                .unwrap_err()
                .to_string()
                .contains("payload exceeds")
        );
    }

    #[test]
    fn batch_and_encoder_reject_payloads_beyond_the_qr_budget() {
        let too_many_parts = (1..=AIRGAP_MAX_CHUNKS + 1)
            .map(|index| format!("{AIRGAP_PREFIX}{index}/{index}:a"))
            .collect::<Vec<_>>();
        assert!(
            parse_airgap_qr_parts(&too_many_parts)
                .unwrap_err()
                .to_string()
                .contains("too many chunks")
        );

        let oversized = AirgapEnvelope::Unsigned(AirgapUnsigned {
            summary: "a".repeat(AIRGAP_MAX_JSON_BYTES),
            ..sample_unsigned()
        });
        assert!(
            encode_envelope_qr(&oversized)
                .unwrap_err()
                .to_string()
                .contains("payload exceeds")
        );
    }
}
