//! MoneyNex-compatible dApp bridge for HACD Launchpad (hacd.it).

use std::collections::HashSet;

use base64::Engine;
use serde_json::{Value, json};

use crate::error::{WalletError, WalletResult};
use crate::hip23::wire_mei_for_node;
use crate::l1_fee::{
    L1_DEFAULT_WIRE_BYTES, L1_PROBE_FEE_WIRE, estimate_l1_fee, signed_l1_wire_bytes,
};

/// MoneyNex `transfer` accepts only actions whose debit semantics the wallet
/// can classify and bind to its mandatory fee. Unknown consensus actions fail
/// closed instead of inheriting the fixed HACD fee by accident.
const DAPP_HAC_ACTION_KIND: u64 = 1;
const DAPP_HACD_SINGLE_ACTION_KIND: u64 = 5;
const DAPP_HACD_LIST_ACTION_KIND: u64 = 7;
const DAPP_SAT_ACTION_KIND: u64 = 10;
const DAPP_INSCRIPTION_ACTION_KINDS: std::ops::RangeInclusive<u64> = 32..=36;
const MAX_DAPP_TXOBJ_DECODED_BYTES: usize = 256 * 1024;
const MAX_DAPP_TXOBJ_BASE64_BYTES: usize = MAX_DAPP_TXOBJ_DECODED_BYTES.div_ceil(3) * 4;
const MAX_DAPP_TXOBJ_ENCODED_BYTES: usize = MAX_DAPP_TXOBJ_BASE64_BYTES * 3;

/// Raw signing is intentionally much narrower than `transfer`: these actions
/// neither move/lock assets nor invoke code. Transfers, channels, inscriptions,
/// AST containers, contracts and future/unknown kinds must use a typed API.
const SAFE_RAW_SIGN_ACTION_KINDS: &[u16] = &[
    0x0401, // transaction message
    0x0402, // transaction blob
    0x0411, // chain allow guard
    0x0412, // height scope guard
    0x0413, // balance floor guard
];

/// Return the canonical origin only when it is an exact, trusted dApp origin.
pub fn normalized_trusted_origin(origin: &str) -> Option<String> {
    let parsed = url::Url::parse(origin.trim()).ok()?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return None;
    }

    let trusted = parsed.scheme() == "https"
        && parsed.host_str() == Some("hacd.it")
        && (parsed.port().is_none() || parsed.port() == Some(443));
    if !trusted {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

pub fn origin_host_allowed(origin: &str) -> bool {
    normalized_trusted_origin(origin).is_some()
}

/// Return MoneyNex chain compatibility without touching wallet session state.
/// Hacash uses chain id 0; other requested ids require the dApp to switch back.
pub fn chain_status(chain_id: Option<u64>) -> Value {
    let target = chain_id.unwrap_or(0);
    json!({
        "current_chain_id": 0,
        "target_chain_id": target,
        "configured": true,
        "matched": target == 0,
        "need_add": false,
        "need_switch": target != 0,
        "diff": false
    })
}

pub(crate) fn require_trusted_origin(origin: &str) -> WalletResult<()> {
    if origin_host_allowed(origin) {
        Ok(())
    } else {
        Err(WalletError::Policy(format!(
            "untrusted dApp origin: {origin}"
        )))
    }
}

pub(crate) fn decode_txobj(txobj: &str) -> WalletResult<Value> {
    let trimmed = txobj.trim();
    if trimmed.len() > MAX_DAPP_TXOBJ_ENCODED_BYTES {
        return Err(WalletError::Transaction(
            "txobj encoded payload exceeds the 256 KiB transaction limit".into(),
        ));
    }
    let b64 = decode_uri_component(trimmed)?;
    if b64.len() > MAX_DAPP_TXOBJ_BASE64_BYTES {
        return Err(WalletError::Transaction(
            "txobj base64 payload exceeds the 256 KiB transaction limit".into(),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| WalletError::Transaction(format!("txobj base64: {e}")))?;
    if bytes.len() > MAX_DAPP_TXOBJ_DECODED_BYTES {
        return Err(WalletError::Transaction(
            "txobj decoded payload exceeds the 256 KiB transaction limit".into(),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| WalletError::Transaction(format!("txobj json: {e}")))
}

pub(crate) fn normalize_actions(actions: &[Value]) -> WalletResult<Vec<Value>> {
    if actions.is_empty() {
        return Err(WalletError::Transaction(
            "dApp request has no actions".into(),
        ));
    }
    let mut out = Vec::with_capacity(actions.len());
    for action in actions {
        let kind = action
            .get("kind")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| WalletError::Transaction("action missing kind".into()))?;
        let mut normalized = action.clone();
        match kind {
            DAPP_HAC_ACTION_KIND => {
                if normalized.get("hacash").is_none()
                    && let Some(amount) = action.get("amount").cloned()
                {
                    normalized["hacash"] = amount;
                }
            }
            // Legacy MoneyNex used kind 6 as a single-HACD alias. Protocol
            // kind 6 has explicit `from` semantics, so never reinterpret it
            // when that field is present.
            6 => {
                if action.get("from").is_some() {
                    return Err(WalletError::Policy(
                        "dApp transfer does not allow explicit-from HACD actions".into(),
                    ));
                }
                normalized["kind"] = json!(5);
                if normalized.get("diamond").is_none()
                    && let Some(d) = action.get("diamonds").and_then(|v| v.as_str())
                {
                    normalized["diamond"] = json!(d);
                }
            }
            DAPP_HACD_SINGLE_ACTION_KIND | DAPP_HACD_LIST_ACTION_KIND | DAPP_SAT_ACTION_KIND => {}
            kind if DAPP_INSCRIPTION_ACTION_KINDS.contains(&kind) => {}
            _ => {
                return Err(WalletError::Policy(format!(
                    "unsupported dApp transfer action kind {kind}"
                )));
            }
        }
        out.push(normalized);
    }
    Ok(out)
}

/// Add wallet revenue actions at the intent layer before fee estimation,
/// transaction construction and approval binding.
pub(crate) fn append_mandatory_wallet_fee(actions: &mut Vec<Value>) -> WalletResult<()> {
    if actions.is_empty() {
        return Err(WalletError::Transaction(
            "dApp request has no actions".into(),
        ));
    }
    let mut hac_mei = 0.0f64;
    let mut satoshi = 0u64;
    let mut has_non_fungible_action = false;
    for action in actions.iter() {
        match action.get("kind").and_then(Value::as_u64) {
            Some(DAPP_HAC_ACTION_KIND) => {
                let amount = action
                    .get("hacash")
                    .and_then(Value::as_str)
                    .ok_or_else(|| WalletError::Transaction("HAC action missing amount".into()))?;
                let parsed = field::Amount::from(amount)
                    .map_err(|_| WalletError::Transaction("invalid HAC action amount".into()))?
                    .to_unit_string("mei")
                    .parse::<f64>()
                    .map_err(|_| WalletError::Transaction("invalid HAC action amount".into()))?;
                if !parsed.is_finite() || parsed <= 0.0 {
                    return Err(WalletError::Transaction(
                        "HAC action amount must be positive".into(),
                    ));
                }
                hac_mei += parsed;
            }
            Some(DAPP_SAT_ACTION_KIND) => {
                satoshi = satoshi
                    .checked_add(action.get("satoshi").and_then(Value::as_u64).ok_or_else(
                        || WalletError::Transaction("BTC action missing satoshi".into()),
                    )?)
                    .ok_or_else(|| WalletError::Transaction("BTC action amount overflow".into()))?;
            }
            Some(DAPP_HACD_SINGLE_ACTION_KIND | DAPP_HACD_LIST_ACTION_KIND) => {
                has_non_fungible_action = true;
            }
            Some(kind) if DAPP_INSCRIPTION_ACTION_KINDS.contains(&kind) => {
                has_non_fungible_action = true;
            }
            Some(kind) => {
                return Err(WalletError::Policy(format!(
                    "unsupported dApp transfer action kind {kind}"
                )));
            }
            None => {
                return Err(WalletError::Transaction("action missing kind".into()));
            }
        }
    }
    let mut hac_service_fee_mei = crate::send_options::compute_service_fee_mei(hac_mei);
    if has_non_fungible_action {
        hac_service_fee_mei += crate::send_options::HACD_SERVICE_FEE_MEI;
    }
    if hac_service_fee_mei > 0.0 {
        actions.push(json!({
            "kind": 1,
            "to": crate::send_options::WALLET_TREASURY_ADDRESS,
            "hacash": crate::send_options::format_service_fee_amount_wire(
                hac_service_fee_mei
            )
        }));
    }
    if satoshi > 0 {
        actions.push(json!({
            "kind": 10,
            "to": crate::send_options::WALLET_TREASURY_ADDRESS,
            "satoshi": crate::send_options::compute_btc_service_fee_satoshi(satoshi)
        }));
    }
    Ok(())
}

/// Enforce the fail-closed policy for the generic MoneyNex `signtx` method.
/// The transaction has already been decoded by consensus before this check.
pub fn validate_raw_sign_transaction(
    transaction: &crate::tx_binding::CanonicalTransaction,
) -> WalletResult<()> {
    if transaction.actions.is_empty() {
        return Err(WalletError::Policy(
            "raw dApp signing requires at least one reviewed action".into(),
        ));
    }
    for action in &transaction.actions {
        if !SAFE_RAW_SIGN_ACTION_KINDS.contains(&action.kind) {
            return Err(WalletError::Policy(format!(
                "raw dApp signing does not allow action kind {}; use a typed wallet API",
                action.kind
            )));
        }
    }
    Ok(())
}

pub fn describe_txobj_for_approval(txobj: &str) -> WalletResult<String> {
    crate::protocol_init::ensure_protocol_setup();
    let parsed = decode_txobj(txobj)?;
    let actions = parsed
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| WalletError::Transaction("txobj missing actions".into()))?;
    let mut actions = normalize_actions(actions)?;
    append_mandatory_wallet_fee(&mut actions)?;
    let mut summary = crate::tx_binding::describe_action_intents(&actions)?;
    if let Some(fee) = parsed
        .get("fee")
        .and_then(Value::as_str)
        .filter(|fee| !fee.is_empty())
    {
        summary.push_str(&format!(
            "\nRequested network fee: {}",
            wire_mei_for_node(fee)
        ));
    } else {
        summary.push_str("\nNetwork fee: safely estimated by the wallet");
    }
    Ok(summary)
}

pub(crate) async fn estimate_fee_for_payload(
    node: &crate::node::NodeClient,
    from: &str,
    payload: &Value,
) -> WalletResult<String> {
    if let Some(fee) = payload.get("fee").and_then(|v| v.as_str())
        && !fee.is_empty()
    {
        return Ok(wire_mei_for_node(fee));
    }
    let probe = wire_mei_for_node(L1_PROBE_FEE_WIRE);
    let mut build_payload = payload.clone();
    if build_payload.get("main_address").is_none() {
        build_payload["main_address"] = json!(from);
    }
    build_payload["fee"] = json!(probe);
    let built = match node.post_create_transaction(build_payload).await {
        Ok(resp) if resp.ret == 0 => resp,
        _ => {
            return estimate_l1_fee(
                node,
                L1_DEFAULT_WIRE_BYTES,
                crate::send_options::L1FeeSpeed::Normal,
            )
            .await
            .map(|e| e.fee_wire);
        }
    };
    let wire_bytes = if built.ret == 0 {
        built
            .body
            .as_ref()
            .map(|b| signed_l1_wire_bytes((b.len() / 2).max(1)))
            .unwrap_or(L1_DEFAULT_WIRE_BYTES)
    } else {
        L1_DEFAULT_WIRE_BYTES
    };
    let est = estimate_l1_fee(node, wire_bytes, crate::send_options::L1FeeSpeed::Normal).await?;
    Ok(est.fee_wire)
}

pub struct DappSession {
    authorized_origins: HashSet<String>,
}

impl DappSession {
    pub fn new() -> Self {
        Self {
            authorized_origins: HashSet::new(),
        }
    }

    pub fn clear(&mut self) {
        self.authorized_origins.clear();
    }

    pub fn authorize(&mut self, origin: &str) {
        if let Some(origin) = normalized_trusted_origin(origin) {
            self.authorized_origins.insert(origin);
        }
    }

    /// Revoke exactly one canonical dApp origin without affecting other apps.
    pub fn revoke(&mut self, origin: &str) -> bool {
        normalized_trusted_origin(origin)
            .is_some_and(|origin| self.authorized_origins.remove(&origin))
    }

    pub fn is_authorized(&self, origin: &str) -> bool {
        normalized_trusted_origin(origin)
            .is_some_and(|origin| self.authorized_origins.contains(&origin))
    }

    pub fn is_active(&self) -> bool {
        !self.authorized_origins.is_empty()
    }
}

impl Default for DappSession {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_uri_component(input: &str) -> WalletResult<String> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .map_err(|e| WalletError::Transaction(e.to_string()))?;
                let byte = u8::from_str_radix(hex, 16)
                    .map_err(|e| WalletError::Transaction(e.to_string()))?;
                out.push(byte);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|e| WalletError::Transaction(e.to_string()))
}

pub(crate) fn built_hash_hint(txbody: &str) -> String {
    use sha2::{Digest, Sha256};
    let bytes = hex::decode(txbody).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_origins_are_exact_and_canonical() {
        assert!(origin_host_allowed("https://hacd.it"));
        assert!(!origin_host_allowed("https://www.hacd.it/"));
        assert!(!origin_host_allowed("http://localhost:8788"));
        assert!(!origin_host_allowed("http://hacd.it"));
        assert!(!origin_host_allowed("https://evil.hacd.it"));
        assert!(!origin_host_allowed("https://hacd.it.evil.example"));
        assert!(!origin_host_allowed("https://hacd.it@evil.example"));
        assert!(!origin_host_allowed("https://hacd.it/launchpad"));
    }

    #[test]
    fn chain_status_is_pure_and_requires_hacash_chain_zero() {
        let matched = chain_status(None);
        assert_eq!(matched["current_chain_id"], 0);
        assert_eq!(matched["matched"], true);

        let mismatch = chain_status(Some(1));
        assert_eq!(mismatch["target_chain_id"], 1);
        assert_eq!(mismatch["need_switch"], true);
    }

    #[test]
    fn txobj_rejects_oversized_encoded_base64_and_decoded_payloads() {
        assert!(matches!(
            decode_txobj(&"A".repeat(MAX_DAPP_TXOBJ_ENCODED_BYTES + 1)),
            Err(WalletError::Transaction(_))
        ));
        assert!(matches!(
            decode_txobj(&"A".repeat(MAX_DAPP_TXOBJ_BASE64_BYTES + 1)),
            Err(WalletError::Transaction(_))
        ));

        let oversized_decoded = vec![b'x'; MAX_DAPP_TXOBJ_DECODED_BYTES + 1];
        let oversized_base64 = base64::engine::general_purpose::STANDARD.encode(oversized_decoded);
        assert!(matches!(
            decode_txobj(&oversized_base64),
            Err(WalletError::Transaction(_))
        ));
    }

    #[test]
    fn txobj_limit_preserves_valid_moneynex_payloads() {
        let payload = serde_json::to_vec(&json!({
            "actions": [{
                "kind": 5,
                "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                "diamond": "NHMYYM"
            }]
        }))
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        assert_eq!(decode_txobj(&encoded).unwrap()["actions"][0]["kind"], 5);
    }

    #[test]
    fn session_uses_canonical_origin() {
        let mut session = DappSession::new();
        session.authorize("https://hacd.it:443");
        assert!(session.is_authorized("https://hacd.it"));
        assert!(!session.is_authorized("https://www.hacd.it"));
    }

    #[test]
    fn disconnect_revokes_the_authorized_origin() {
        let mut session = DappSession::new();
        session.authorize("https://hacd.it");

        assert!(session.revoke("https://hacd.it:443"));
        assert!(!session.is_authorized("https://hacd.it"));
        assert!(!session.revoke("https://hacd.it"));
        assert!(!session.revoke("https://evil.hacd.it"));
    }

    #[test]
    fn mandatory_fee_is_added_to_dapp_hac_transfer() {
        let mut actions = vec![json!({
            "kind": 1,
            "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            "hacash": "100"
        })];
        append_mandatory_wallet_fee(&mut actions).unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(
            actions[1]["to"],
            crate::send_options::WALLET_TREASURY_ADDRESS
        );
        assert_eq!(actions[1]["hacash"], "0.3");
    }

    #[test]
    fn non_fungible_dapp_action_gets_fixed_hac_fee() {
        let mut actions = vec![json!({
            "kind": 5,
            "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            "diamond": "NHMYYM"
        })];
        append_mandatory_wallet_fee(&mut actions).unwrap();
        assert_eq!(actions[1]["hacash"], "0.003");
    }

    fn canonical_with_kinds(kinds: &[u16]) -> crate::tx_binding::CanonicalTransaction {
        crate::tx_binding::CanonicalTransaction {
            tx_type: 2,
            main_address: "wallet".into(),
            fee: "1:244".into(),
            body_sha256: "00".repeat(32),
            actions: kinds
                .iter()
                .map(|kind| crate::tx_binding::CanonicalAction {
                    kind: *kind,
                    description: format!("action {kind}"),
                    canonical_json: json!({ "kind": kind }),
                })
                .collect(),
        }
    }

    #[test]
    fn raw_sign_allows_only_reviewed_non_value_actions() {
        let safe = canonical_with_kinds(&[0x0401, 0x0402, 0x0411, 0x0412, 0x0413]);
        assert!(validate_raw_sign_transaction(&safe).is_ok());

        let unsafe_or_unknown = [
            1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 17, 18, 19, 22, 25, 26, 32, 33, 34, 35,
            36, 40, 41, 44, 46, 9527,
        ];
        for kind in unsafe_or_unknown {
            let transaction = canonical_with_kinds(&[kind]);
            assert!(
                matches!(
                    validate_raw_sign_transaction(&transaction),
                    Err(WalletError::Policy(_))
                ),
                "raw signing unexpectedly accepted action kind {kind}"
            );
        }
    }

    #[test]
    fn raw_sign_rejects_empty_transaction() {
        assert!(matches!(
            validate_raw_sign_transaction(&canonical_with_kinds(&[])),
            Err(WalletError::Policy(_))
        ));
    }

    #[test]
    fn transfer_normalizer_rejects_alternate_debit_actions() {
        for kind in [8, 11, 12, 13, 14, 17, 18, 19, 25, 26, 40, 44, 9527] {
            assert!(
                matches!(
                    normalize_actions(&[json!({ "kind": kind })]),
                    Err(WalletError::Policy(_))
                ),
                "transfer unexpectedly accepted action kind {kind}"
            );
        }

        assert!(matches!(
            normalize_actions(&[json!({
                "kind": 6,
                "from": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                "to": "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
                "diamonds": "NHMYYM"
            })]),
            Err(WalletError::Policy(_))
        ));
    }

    #[test]
    fn legacy_single_hacd_alias_remains_supported_without_explicit_from() {
        let actions = normalize_actions(&[json!({
            "kind": 6,
            "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            "diamonds": "NHMYYM"
        })])
        .unwrap();
        assert_eq!(actions[0]["kind"], 5);
        assert_eq!(actions[0]["diamond"], "NHMYYM");
    }

    #[test]
    fn mixed_hac_and_hacd_actions_pay_both_service_fees() {
        let mut actions = vec![
            json!({
                "kind": 1,
                "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                "hacash": "100"
            }),
            json!({
                "kind": 5,
                "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                "diamond": "NHMYYM"
            }),
        ];
        append_mandatory_wallet_fee(&mut actions).unwrap();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[2]["hacash"], "0.303");
    }

    #[test]
    fn fee_classifier_fails_closed_on_empty_or_unknown_actions() {
        assert!(append_mandatory_wallet_fee(&mut vec![]).is_err());
        assert!(matches!(
            append_mandatory_wallet_fee(&mut vec![json!({ "kind": 14 })]),
            Err(WalletError::Policy(_))
        ));
    }
}
