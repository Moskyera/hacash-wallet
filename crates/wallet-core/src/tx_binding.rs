//! Canonical transaction decoding and intent binding.
//!
//! The public node may construct unsigned transaction bodies, but it is never
//! trusted to decide what the wallet signs. Every body is decoded with the
//! consensus codecs and compared with locally decoded action intents first.

use basis::interface::{Action, TransactionRead};
use field::Amount;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};

const MAX_UNSIGNED_TX_BYTES: usize = 256 * 1024;
const MAX_ACTIONS: usize = 200;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CanonicalTransaction {
    pub tx_type: u8,
    pub main_address: String,
    pub fee: String,
    pub body_sha256: String,
    pub actions: Vec<CanonicalAction>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CanonicalAction {
    pub kind: u16,
    pub description: String,
    pub canonical_json: Value,
}

impl CanonicalTransaction {
    /// True when this body is a proof-of-ownership challenge rather than a payment: a single HAC
    /// transfer whose sender, recipient and signing address are all identical. Signing it proves
    /// control of the key while nothing moves anywhere the signer does not already control.
    /// Harbor issues exactly this shape for login and vault authorisation, and naming it plainly
    /// is what lets a signer approve with confidence instead of squinting at a raw transfer.
    pub fn is_ownership_proof(&self) -> bool {
        if self.actions.len() != 1 {
            return false;
        }
        let action = &self.actions[0];
        if action.kind != 14 {
            return false;
        }
        let from = action.canonical_json.get("from").and_then(Value::as_str);
        let to = action.canonical_json.get("to").and_then(Value::as_str);
        matches!((from, to), (Some(f), Some(t)) if f == t && f == self.main_address)
    }

    pub fn approval_summary(&self) -> String {
        let mut lines = Vec::new();
        if self.is_ownership_proof() {
            lines.push(
                "Proof of ownership — you are proving you control this address. \
                 No funds leave your wallet."
                    .to_string(),
            );
        }
        lines.push(format!("From: {}", self.main_address));
        lines.push(format!("Network fee: {}", self.fee));
        for (index, action) in self.actions.iter().enumerate() {
            lines.push(format!("Action {}: {}", index + 1, action.description));
        }
        lines.push(format!("Body SHA-256: {}", self.body_sha256));
        lines.join("\n")
    }
}

pub fn decode_transaction(body_hex: &str) -> WalletResult<CanonicalTransaction> {
    let (tx, raw) = parse_transaction(body_hex)?;
    canonical_from_tx(tx.as_read(), &raw)
}

pub fn verify_transaction_intent(
    body_hex: &str,
    expected_main: &str,
    expected_fee: &str,
    expected_actions: &[Value],
) -> WalletResult<CanonicalTransaction> {
    let (tx, raw) = parse_transaction(body_hex)?;
    let canonical = canonical_from_tx(tx.as_read(), &raw)?;

    if canonical.main_address != expected_main {
        return Err(binding_error(format!(
            "main address mismatch: approved {expected_main}, body has {}",
            canonical.main_address
        )));
    }

    let expected_fee = parse_amount(expected_fee, "fee")?;
    if tx.fee() != &expected_fee {
        return Err(binding_error(format!(
            "fee mismatch: approved {}, body has {}",
            expected_fee.to_fin_string(),
            tx.fee().to_fin_string()
        )));
    }

    if tx.actions().len() != expected_actions.len() {
        return Err(binding_error(format!(
            "action count mismatch: approved {}, body has {}",
            expected_actions.len(),
            tx.actions().len()
        )));
    }

    for (index, (actual, expected_json)) in
        tx.actions().iter().zip(expected_actions.iter()).enumerate()
    {
        let expected = decode_expected_action(expected_json, index)?;
        if actual.serialize() != expected.serialize() {
            return Err(binding_error(format!(
                "action {} differs from the approved request",
                index + 1
            )));
        }
    }

    Ok(canonical)
}

pub fn verify_hac_transfers(
    body_hex: &str,
    expected_main: &str,
    expected_fee: &str,
    transfers: &[(&str, &str)],
) -> WalletResult<CanonicalTransaction> {
    let actions = transfers
        .iter()
        .map(|(to, amount)| {
            json!({
                "kind": 1,
                "to": to,
                "hacash": amount
            })
        })
        .collect::<Vec<_>>();
    verify_transaction_intent(body_hex, expected_main, expected_fee, &actions)
}

pub fn verify_hacd_transfer(
    body_hex: &str,
    expected_main: &str,
    expected_fee: &str,
    to: &str,
    diamond_names: &[String],
) -> WalletResult<CanonicalTransaction> {
    let action = if diamond_names.len() == 1 {
        json!({
            "kind": 5,
            "to": to,
            "diamond": diamond_names[0]
        })
    } else {
        json!({
            "kind": 7,
            "to": to,
            "diamonds": diamond_names.join("")
        })
    };
    verify_transaction_intent(body_hex, expected_main, expected_fee, &[action])
}

pub fn verify_hacd_transfer_with_service_fee(
    body_hex: &str,
    expected_main: &str,
    expected_fee: &str,
    to: &str,
    diamond_names: &[String],
    service_fee: &str,
) -> WalletResult<CanonicalTransaction> {
    let diamond_action = if diamond_names.len() == 1 {
        json!({ "kind": 5, "to": to, "diamond": diamond_names[0] })
    } else {
        json!({ "kind": 7, "to": to, "diamonds": diamond_names.join("") })
    };
    verify_transaction_intent(
        body_hex,
        expected_main,
        expected_fee,
        &[
            diamond_action,
            json!({
                "kind": 1,
                "to": crate::send_options::WALLET_TREASURY_ADDRESS,
                "hacash": service_fee
            }),
        ],
    )
}

pub fn verify_satoshi_transfer(
    body_hex: &str,
    expected_main: &str,
    expected_fee: &str,
    to: &str,
    satoshi: u64,
) -> WalletResult<CanonicalTransaction> {
    verify_transaction_intent(
        body_hex,
        expected_main,
        expected_fee,
        &[json!({
            "kind": 10,
            "to": to,
            "satoshi": satoshi
        })],
    )
}

pub fn verify_satoshi_transfers(
    body_hex: &str,
    expected_main: &str,
    expected_fee: &str,
    transfers: &[(&str, u64)],
) -> WalletResult<CanonicalTransaction> {
    let actions = transfers
        .iter()
        .map(|(to, satoshi)| {
            json!({
                "kind": 10,
                "to": to,
                "satoshi": satoshi
            })
        })
        .collect::<Vec<_>>();
    verify_transaction_intent(body_hex, expected_main, expected_fee, &actions)
}

pub fn describe_action_intents(actions: &[Value]) -> WalletResult<String> {
    if actions.is_empty() {
        return Err(binding_error("dApp request has no actions"));
    }
    if actions.len() > MAX_ACTIONS {
        return Err(WalletError::Transaction(
            "dApp request has too many actions".into(),
        ));
    }
    let mut lines = Vec::with_capacity(actions.len());
    for (index, value) in actions.iter().enumerate() {
        let action = decode_expected_action(value, index)?;
        let canonical = canonical_action(action.as_ref())?;
        lines.push(format!("Action {}: {}", index + 1, canonical.description));
    }
    Ok(lines.join("\n"))
}

pub fn validate_signer_body(
    body_hex: &str,
    expected_main: &str,
) -> WalletResult<CanonicalTransaction> {
    let canonical = decode_transaction(body_hex)?;
    if canonical.main_address != expected_main {
        return Err(binding_error(format!(
            "signer address mismatch: wallet {expected_main}, body main address {}",
            canonical.main_address
        )));
    }
    if canonical.actions.is_empty() {
        return Err(binding_error("transaction has no actions"));
    }
    Ok(canonical)
}

fn parse_transaction(
    body_hex: &str,
) -> WalletResult<(Box<dyn basis::interface::Transaction>, Vec<u8>)> {
    if body_hex.len() > MAX_UNSIGNED_TX_BYTES * 2 {
        return Err(WalletError::Transaction(
            "transaction body is too large".into(),
        ));
    }
    let raw = hex::decode(body_hex)
        .map_err(|e| WalletError::Transaction(format!("transaction hex: {e}")))?;
    if raw.is_empty() {
        return Err(WalletError::Transaction("transaction body is empty".into()));
    }
    let (tx, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|e| WalletError::Transaction(e.to_string()))?;
    if consumed != raw.len() {
        return Err(WalletError::Transaction(format!(
            "transaction has {} trailing byte(s)",
            raw.len() - consumed
        )));
    }
    if tx.actions().len() > MAX_ACTIONS {
        return Err(WalletError::Transaction(
            "transaction has too many actions".into(),
        ));
    }
    Ok((tx, raw))
}

fn canonical_from_tx(tx: &dyn TransactionRead, raw: &[u8]) -> WalletResult<CanonicalTransaction> {
    let actions = tx
        .actions()
        .iter()
        .map(|action| canonical_action(action.as_ref()))
        .collect::<WalletResult<Vec<_>>>()?;
    Ok(CanonicalTransaction {
        tx_type: tx.ty(),
        main_address: tx.main().to_readable(),
        fee: tx.fee().to_fin_string(),
        body_sha256: hex::encode(Sha256::digest(raw)),
        actions,
    })
}

fn canonical_action(action: &dyn Action) -> WalletResult<CanonicalAction> {
    let json = action.to_json();
    let canonical_json = serde_json::from_str(&json).map_err(|e| {
        WalletError::Transaction(format!("action {} canonical JSON: {e}", action.kind()))
    })?;
    let description = action.to_description();
    Ok(CanonicalAction {
        kind: action.kind(),
        description: if description.trim().is_empty() {
            format!("Hacash action kind {}", action.kind())
        } else {
            description
        },
        canonical_json,
    })
}

fn decode_expected_action(value: &Value, index: usize) -> WalletResult<Box<dyn Action>> {
    let object = value
        .as_object()
        .ok_or_else(|| binding_error(format!("approved action {} is not an object", index + 1)))?;
    let kind = object.get("kind").and_then(Value::as_u64).ok_or_else(|| {
        binding_error(format!("approved action {} has no numeric kind", index + 1))
    })?;
    if kind > u16::MAX as u64 {
        return Err(binding_error(format!(
            "approved action {} kind is out of range",
            index + 1
        )));
    }
    let json = serde_json::to_string(value)
        .map_err(|e| WalletError::Transaction(format!("approved action JSON: {e}")))?;
    protocol::action::action_json_create(kind as u16, &json)
        .map_err(|e| binding_error(format!("approved action {} is invalid: {e}", index + 1)))?
        .ok_or_else(|| binding_error(format!("approved action kind {kind} is unsupported")))
}

fn parse_amount(value: &str, label: &str) -> WalletResult<Amount> {
    Amount::from(value)
        .map_err(|e| WalletError::Transaction(format!("invalid {label} amount: {e}")))
}

fn binding_error(message: impl Into<String>) -> WalletError {
    WalletError::Policy(format!(
        "transaction intent verification failed: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OFFICIAL_NODE_HAC_BODY: &str = "02006a59827900681990afd226b1cbc6c5f085cfdc2092d0843241f401010001000100d3234881daaf07d4562308104401b003328c3744f8010100000000";

    // A real Harbor proof-of-ownership challenge built by the node: a kind-14 HAC transfer from
    // 1MzNY1oA…zXHzK9 to itself. Signing it proves control of the key without moving funds.
    const HARBOR_OWNERSHIP_PROOF_BODY: &str = "02006553f16300e63c33a796b3032ce6b856f68fccf06608d9ed18f401010001000e00e63c33a796b3032ce6b856f68fccf06608d9ed1800e63c33a796b3032ce6b856f68fccf06608d9ed18f0010100000000";

    #[test]
    fn harbor_self_transfer_is_recognised_as_an_ownership_proof() {
        crate::protocol_init::ensure_protocol_setup();
        let canonical = decode_transaction(HARBOR_OWNERSHIP_PROOF_BODY).unwrap();
        assert_eq!(canonical.actions.len(), 1);
        assert_eq!(canonical.actions[0].kind, 14, "HAC_FROM_TO decodes to kind 14");
        assert!(canonical.is_ownership_proof(), "from == to == signer");
        assert!(
            canonical.approval_summary().starts_with("Proof of ownership"),
            "the signer is told plainly what they are approving"
        );
    }

    #[test]
    fn an_ordinary_transfer_is_not_an_ownership_proof() {
        crate::protocol_init::ensure_protocol_setup();
        // OFFICIAL_NODE_HAC_BODY pays a different recipient — a real payment, not a proof.
        let canonical = decode_transaction(OFFICIAL_NODE_HAC_BODY).unwrap();
        assert!(!canonical.is_ownership_proof());
        assert!(!canonical.approval_summary().starts_with("Proof of ownership"));
    }

    #[test]
    fn official_node_hac_body_matches_exact_intent() {
        crate::protocol_init::ensure_protocol_setup();
        let summary = verify_transaction_intent(
            OFFICIAL_NODE_HAC_BODY,
            "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            "1:244",
            &[json!({
                "kind": 1,
                "to": "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
                "hacash": "1"
            })],
        )
        .unwrap();
        assert_eq!(summary.actions.len(), 1);
        assert_eq!(summary.actions[0].kind, 1);
    }

    #[test]
    fn recipient_and_fee_substitution_are_rejected() {
        crate::protocol_init::ensure_protocol_setup();
        let wrong_recipient = verify_transaction_intent(
            OFFICIAL_NODE_HAC_BODY,
            "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            "1:244",
            &[json!({
                "kind": 1,
                "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                "hacash": "1"
            })],
        )
        .unwrap_err();
        assert!(matches!(wrong_recipient, WalletError::Policy(_)));

        let wrong_fee = verify_transaction_intent(
            OFFICIAL_NODE_HAC_BODY,
            "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            "2:244",
            &[json!({
                "kind": 1,
                "to": "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
                "hacash": "1"
            })],
        )
        .unwrap_err();
        assert!(matches!(wrong_fee, WalletError::Policy(_)));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        crate::protocol_init::ensure_protocol_setup();
        let body = format!("{OFFICIAL_NODE_HAC_BODY}00");
        assert!(decode_transaction(&body).is_err());
    }
}
