//! Canonical transaction decoding and intent binding.
//!
//! The public node may construct unsigned transaction bodies, but it is never
//! trusted to decide what the wallet signs. Every body is decoded with the
//! consensus codecs and compared with locally decoded action intents first.

use basis::interface::{Action, TransactionRead};
use field::Amount;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};

const MAX_UNSIGNED_TX_BYTES: usize = 256 * 1024;
const MAX_ACTIONS: usize = 200;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CanonicalTransaction {
    pub tx_type: u8,
    pub gas_max: Option<u8>,
    pub main_address: String,
    pub fee: String,
    pub body_sha256: String,
    pub required_signers: Vec<String>,
    pub signer_policy: SignerPolicy,
    pub actions: Vec<CanonicalAction>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerPolicy {
    /// Legacy Type 1/2 and Type 4 require at least the reported signer set.
    AtLeast,
    /// Istanbul Type 3 requires the reported signer set exactly, including ReqSignList.
    Exact,
}

/// Values the wallet approved before asking a node to construct a transaction.
/// A chain id is bound by requiring one exact ChainAllow guard in the action list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExpectedTransaction {
    pub tx_type: u8,
    #[serde(default)]
    pub gas_max: Option<u8>,
    #[serde(default)]
    pub chain_id: Option<u32>,
    pub main_address: String,
    pub fee: String,
    pub actions: Vec<Value>,
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
                "Proof of ownership: you are proving you control this address. \
                 No funds leave your wallet."
                    .to_string(),
            );
        }
        lines.push(format!("Transaction type: {}", self.tx_type));
        if let Some(gas_max) = self.gas_max {
            lines.push(format!("Gas limit byte: {gas_max}"));
        }
        lines.push(format!("From: {}", self.main_address));
        lines.push(format!("Network fee: {}", self.fee));
        if !self.required_signers.is_empty() {
            let rule = match self.signer_policy {
                SignerPolicy::AtLeast => "at least",
                SignerPolicy::Exact => "exactly",
            };
            lines.push(format!(
                "Required signers ({rule}): {}",
                self.required_signers.join(", ")
            ));
        }
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

/// Decode a transaction for UI inspection and optionally require one exact chain guard.
pub fn inspect_transaction(
    body_hex: &str,
    expected_chain_id: Option<u32>,
) -> WalletResult<CanonicalTransaction> {
    let canonical = decode_transaction(body_hex)?;
    if let Some(chain_id) = expected_chain_id {
        verify_exact_chain_guard(chain_id, &canonical.actions)?;
    }
    Ok(canonical)
}

pub fn verify_expected_transaction(
    body_hex: &str,
    expected: &ExpectedTransaction,
) -> WalletResult<CanonicalTransaction> {
    let (tx, raw) = parse_transaction(body_hex)?;
    if tx.ty() != expected.tx_type {
        return Err(binding_error(format!(
            "transaction type mismatch: approved {}, body has {}",
            expected.tx_type,
            tx.ty()
        )));
    }
    if tx.gas_max_byte() != expected.gas_max {
        return Err(binding_error(format!(
            "gas_max mismatch: approved {:?}, body has {:?}",
            expected.gas_max,
            tx.gas_max_byte()
        )));
    }
    let canonical = verify_decoded_intent(
        tx.as_read(),
        &raw,
        &expected.main_address,
        &expected.fee,
        &expected.actions,
    )?;
    if let Some(chain_id) = expected.chain_id {
        verify_exact_chain_guard(chain_id, &canonical.actions)?;
    }
    Ok(canonical)
}

pub fn verify_transaction_intent(
    body_hex: &str,
    expected_main: &str,
    expected_fee: &str,
    expected_actions: &[Value],
) -> WalletResult<CanonicalTransaction> {
    let (tx, raw) = parse_transaction(body_hex)?;
    verify_decoded_intent(
        tx.as_read(),
        &raw,
        expected_main,
        expected_fee,
        expected_actions,
    )
}

fn verify_decoded_intent(
    tx: &dyn TransactionRead,
    raw: &[u8],
    expected_main: &str,
    expected_fee: &str,
    expected_actions: &[Value],
) -> WalletResult<CanonicalTransaction> {
    let canonical = canonical_from_tx(tx, raw)?;
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

fn verify_exact_chain_guard(chain_id: u32, actions: &[CanonicalAction]) -> WalletResult<()> {
    const CHAIN_ALLOW_KIND: u16 = 0x0411;
    let guards = actions
        .iter()
        .filter(|action| action.kind == CHAIN_ALLOW_KIND)
        .collect::<Vec<_>>();
    if guards.len() != 1 {
        return Err(binding_error(format!(
            "chain {chain_id} requires exactly one ChainAllow guard"
        )));
    }
    let chains = guards[0]
        .canonical_json
        .get("chains")
        .and_then(Value::as_array)
        .ok_or_else(|| binding_error("ChainAllow guard has no canonical chains array"))?;
    let exact = chains.len() == 1
        && chains[0]
            .as_u64()
            .is_some_and(|actual| actual == u64::from(chain_id));
    if !exact {
        return Err(binding_error(format!(
            "ChainAllow must bind exactly chain {chain_id}"
        )));
    }
    Ok(())
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
    crate::protocol_init::ensure_protocol_setup();
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
    protocol::action::precheck_tx_actions(tx.ty(), tx.actions()).map_err(|error| {
        WalletError::Policy(format!("consensus action topology rejected: {error}"))
    })?;
    Ok((tx, raw))
}

fn canonical_from_tx(tx: &dyn TransactionRead, raw: &[u8]) -> WalletResult<CanonicalTransaction> {
    let actions = tx
        .actions()
        .iter()
        .map(|action| canonical_action(action.as_ref()))
        .collect::<WalletResult<Vec<_>>>()?;
    let mut required_signers = tx
        .req_sign()
        .map_err(|error| {
            WalletError::Policy(format!("required signer analysis rejected: {error}"))
        })?
        .into_iter()
        .map(|address| address.to_readable())
        .collect::<Vec<_>>();
    required_signers.sort();
    Ok(CanonicalTransaction {
        tx_type: tx.ty(),
        gas_max: tx.gas_max_byte(),
        main_address: tx.main().to_readable(),
        fee: tx.fee().to_fin_string(),
        body_sha256: hex::encode(Sha256::digest(raw)),
        required_signers,
        signer_policy: if tx.ty() == 3 {
            SignerPolicy::Exact
        } else {
            SignerPolicy::AtLeast
        },
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
    use basis::interface::Transaction;
    use field::{Address, Uint1};
    use protocol::action::ReqSignList;
    use protocol::transaction::TransactionType3;
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
        assert_eq!(
            canonical.actions[0].kind, 14,
            "HAC_FROM_TO decodes to kind 14"
        );
        assert!(canonical.is_ownership_proof(), "from == to == signer");
        assert!(
            canonical
                .approval_summary()
                .starts_with("Proof of ownership"),
            "the signer is told plainly what they are approving"
        );
    }

    #[test]
    fn an_ordinary_transfer_is_not_an_ownership_proof() {
        crate::protocol_init::ensure_protocol_setup();
        // OFFICIAL_NODE_HAC_BODY pays a different recipient, so it is a payment, not a proof.
        let canonical = decode_transaction(OFFICIAL_NODE_HAC_BODY).unwrap();
        assert!(!canonical.is_ownership_proof());
        assert!(
            !canonical
                .approval_summary()
                .starts_with("Proof of ownership")
        );
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

    fn type3_with_actions(main: Address, actions: Vec<Box<dyn Action>>, gas_max: u8) -> String {
        let mut tx = TransactionType3::new_by(main, Amount::from("1:244").unwrap(), 1_700_000_000);
        tx.gas_max = Uint1::from(gas_max);
        for action in actions {
            tx.push_action(action).unwrap();
        }
        hex::encode(field::Serialize::serialize(&tx))
    }

    fn hac_to(address: Address) -> Box<dyn Action> {
        let value = json!({
            "kind": 1,
            "to": address.to_readable(),
            "hacash": "1"
        });
        protocol::action::action_json_create(1, &value.to_string())
            .unwrap()
            .unwrap()
    }

    #[test]
    fn hvm_action_is_decoded_for_review_without_local_execution() {
        crate::protocol_init::ensure_protocol_setup();
        let main = Address::create_privakey([31; 20]);
        // 0xff is intentionally not validated or executed by the wallet decoder.
        let call = vm::action::ContractMainCall::from_bytecode(vec![0xff]).unwrap();
        let body = type3_with_actions(main, vec![Box::new(call)], 17);

        let canonical = decode_transaction(&body).unwrap();
        assert_eq!(canonical.tx_type, 3);
        assert_eq!(canonical.gas_max, Some(17));
        assert_eq!(canonical.actions.len(), 1);
        assert_eq!(canonical.actions[0].kind, 44);
        assert_eq!(canonical.signer_policy, SignerPolicy::Exact);
    }

    #[test]
    fn type3_signer_report_uses_exact_reqsignlist_semantics() {
        crate::protocol_init::ensure_protocol_setup();
        let main = Address::create_privakey([41; 20]);
        let recipient = Address::create_privakey([42; 20]);
        let extra = Address::create_privakey([43; 20]);
        let declared = ReqSignList::create_by_addrs(vec![extra]).unwrap();
        let body = type3_with_actions(main, vec![hac_to(recipient), Box::new(declared)], 9);

        let canonical = decode_transaction(&body).unwrap();
        let mut expected = vec![main.to_readable(), extra.to_readable()];
        expected.sort();
        assert_eq!(canonical.required_signers, expected);
        assert_eq!(canonical.signer_policy, SignerPolicy::Exact);
    }

    #[test]
    fn type3_reqsignlist_overlap_is_rejected_during_review() {
        crate::protocol_init::ensure_protocol_setup();
        let main = Address::create_privakey([51; 20]);
        let recipient = Address::create_privakey([52; 20]);
        let overlapping = ReqSignList::create_by_addrs(vec![main]).unwrap();
        let body = type3_with_actions(main, vec![hac_to(recipient), Box::new(overlapping)], 9);
        assert!(matches!(
            decode_transaction(&body),
            Err(WalletError::Policy(_))
        ));
    }

    #[test]
    fn expected_transaction_binds_type_gas_chain_main_fee_and_actions() {
        crate::protocol_init::ensure_protocol_setup();
        let main = Address::create_privakey([61; 20]);
        let recipient = Address::create_privakey([62; 20]);
        let transfer = json!({
            "kind": 1,
            "to": recipient.to_readable(),
            "hacash": "1"
        });
        let chain_guard = json!({ "kind": 0x0411, "chains": [0] });
        let guard = protocol::action::action_json_create(0x0411, &chain_guard.to_string())
            .unwrap()
            .unwrap();
        let body = type3_with_actions(main, vec![hac_to(recipient), guard], 17);
        let expected = ExpectedTransaction {
            tx_type: 3,
            gas_max: Some(17),
            chain_id: Some(0),
            main_address: main.to_readable(),
            fee: "1:244".into(),
            actions: vec![transfer, chain_guard],
        };

        let canonical = verify_expected_transaction(&body, &expected).unwrap();
        assert_eq!(canonical.tx_type, 3);
        assert_eq!(canonical.gas_max, Some(17));

        let mut wrong_type = expected.clone();
        wrong_type.tx_type = 2;
        assert!(verify_expected_transaction(&body, &wrong_type).is_err());
        let mut wrong_gas = expected.clone();
        wrong_gas.gas_max = Some(16);
        assert!(verify_expected_transaction(&body, &wrong_gas).is_err());
        let mut wrong_chain = expected;
        wrong_chain.chain_id = Some(1);
        assert!(verify_expected_transaction(&body, &wrong_chain).is_err());
    }

    #[test]
    fn unknown_action_intents_remain_fail_closed() {
        crate::protocol_init::ensure_protocol_setup();
        assert!(decode_expected_action(&json!({ "kind": 65535 }), 0).is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        crate::protocol_init::ensure_protocol_setup();
        let body = format!("{OFFICIAL_NODE_HAC_BODY}00");
        assert!(decode_transaction(&body).is_err());
    }
}
