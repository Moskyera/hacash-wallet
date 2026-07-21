//! MoneyNex-compatible dApp bridge for HACD Launchpad (hacd.it).

use std::collections::HashSet;

use base64::Engine;
use serde_json::{Value, json};

use crate::error::{WalletError, WalletResult};
use crate::hip23::wire_mei_for_node;
use crate::l1_fee::{
    L1_DEFAULT_WIRE_BYTES, L1_PROBE_FEE_WIRE, estimate_l1_fee, signed_l1_wire_bytes,
};
use crate::node_capabilities::{CapabilitySource, NodeCapabilities};

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

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DappTransferIntent {
    pub tx_type: u8,
    pub gas_max: Option<u8>,
    pub chain_id: Option<u32>,
    pub actions: Vec<Value>,
}

fn optional_u64_field(value: &Value, name: &str) -> WalletResult<Option<u64>> {
    let Some(field) = value.get(name) else {
        return Ok(None);
    };
    field
        .as_u64()
        .map(Some)
        .ok_or_else(|| WalletError::Transaction(format!("dApp {name} must be an unsigned integer")))
}

/// Normalize all transaction-level fields before approval, node construction and binding.
pub(crate) fn prepare_transfer_intent(parsed: &Value) -> WalletResult<DappTransferIntent> {
    if !parsed.is_object() {
        return Err(WalletError::Transaction(
            "dApp txobj must be a JSON object".into(),
        ));
    }
    let primary_type = optional_u64_field(parsed, "tx_type")?;
    let alias_type = optional_u64_field(parsed, "type")?;
    if primary_type.is_some() && alias_type.is_some() && primary_type != alias_type {
        return Err(WalletError::Transaction(
            "dApp tx_type and type fields disagree".into(),
        ));
    }
    let tx_type = u8::try_from(primary_type.or(alias_type).unwrap_or(2))
        .map_err(|_| WalletError::Transaction("dApp tx_type is out of range".into()))?;
    if !matches!(tx_type, 2 | 3) {
        return Err(WalletError::Policy(format!(
            "dApp transfer transaction type {tx_type} is not supported"
        )));
    }

    let requested_gas = optional_u64_field(parsed, "gas_max")?;
    let gas_max = match tx_type {
        2 if requested_gas.is_some() => {
            return Err(WalletError::Policy(
                "Type 2 dApp transactions must not include gas_max".into(),
            ));
        }
        2 => None,
        3 => {
            let gas = requested_gas.unwrap_or(0);
            if gas > u64::from(protocol::context::TX_GAS_BUDGET_CAP_BYTE) {
                return Err(WalletError::Policy(format!(
                    "dApp gas_max exceeds the local cap {}",
                    protocol::context::TX_GAS_BUDGET_CAP_BYTE
                )));
            }
            Some(gas as u8)
        }
        _ => unreachable!(),
    };
    let chain_id = optional_u64_field(parsed, "chain_id")?
        .map(|chain| {
            u32::try_from(chain)
                .map_err(|_| WalletError::Transaction("dApp chain_id is out of range".into()))
        })
        .transpose()?;
    if tx_type == 3 && chain_id.is_none() {
        return Err(WalletError::Policy(
            "Type 3 dApp transactions require an explicit chain_id".into(),
        ));
    }

    let actions = parsed
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| WalletError::Transaction("txobj missing actions".into()))?;
    let mut actions = normalize_actions(actions)?;
    append_mandatory_wallet_fee(&mut actions)?;
    if let Some(chain_id) = chain_id {
        actions.insert(0, json!({ "kind": 0x0411, "chains": [chain_id] }));
    }
    Ok(DappTransferIntent {
        tx_type,
        gas_max,
        chain_id,
        actions,
    })
}

pub(crate) fn validate_transfer_capabilities(
    intent: &DappTransferIntent,
    capabilities: &NodeCapabilities,
) -> WalletResult<()> {
    if intent.tx_type == 3 {
        if capabilities.source != CapabilitySource::Reported {
            return Err(WalletError::Policy(
                "Type 3 requires a node with reported Istanbul capabilities".into(),
            ));
        }
        if !capabilities.istanbul.active {
            return Err(WalletError::Policy(
                "Type 3 is not enabled while Istanbul is inactive".into(),
            ));
        }
    }
    if !capabilities.supports_transaction(intent.tx_type) {
        return Err(WalletError::Policy(format!(
            "node does not enable transaction type {}",
            intent.tx_type
        )));
    }
    if capabilities.source == CapabilitySource::LegacyType2 {
        if intent.tx_type != 2 || intent.chain_id.is_some() {
            return Err(WalletError::Policy(
                "Istanbul dApp fields require a node with reported capabilities".into(),
            ));
        }
        return Ok(());
    }
    if let Some(chain_id) = intent.chain_id
        && chain_id != capabilities.chain.id
    {
        return Err(WalletError::Policy(format!(
            "dApp requested chain {chain_id}, but the node reports chain {}",
            capabilities.chain.id
        )));
    }
    if intent.actions.len() > capabilities.limits.max_tx_actions {
        return Err(WalletError::Policy(
            "dApp action count exceeds node limits".into(),
        ));
    }
    if intent
        .gas_max
        .is_some_and(|gas| gas > capabilities.limits.gas_max_byte)
    {
        return Err(WalletError::Policy(
            "dApp gas_max exceeds node limits".into(),
        ));
    }
    for action in &intent.actions {
        let kind = action
            .get("kind")
            .and_then(Value::as_u64)
            .and_then(|kind| u16::try_from(kind).ok())
            .ok_or_else(|| WalletError::Transaction("dApp action kind is invalid".into()))?;
        if !capabilities.supports_action(kind) {
            return Err(WalletError::Policy(format!(
                "node does not enable action kind {kind}"
            )));
        }
    }
    Ok(())
}

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
/// This compatibility helper remains for callers without a capability probe.
pub fn chain_status(chain_id: Option<u64>) -> Value {
    chain_status_for_node(chain_id, Some(0), "static")
}

/// Return chain compatibility using the selected node's validated capability report.
pub fn chain_status_for_node(
    chain_id: Option<u64>,
    current_chain_id: Option<u32>,
    capability_source: &str,
) -> Value {
    let Some(current_chain_id) = current_chain_id else {
        return json!({
            "current_chain_id": Value::Null,
            "target_chain_id": chain_id,
            "configured": false,
            "matched": false,
            "need_add": false,
            "need_switch": false,
            "diff": false,
            "capability_source": capability_source
        });
    };
    let target = chain_id.unwrap_or(u64::from(current_chain_id));
    let matched = target == u64::from(current_chain_id);
    json!({
        "current_chain_id": current_chain_id,
        "target_chain_id": target,
        "configured": true,
        "matched": matched,
        "need_add": false,
        "need_switch": !matched,
        "diff": false,
        "capability_source": capability_source
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
/// Istanbul Type 3 needs a non-guard leaf. The currently reviewed raw-sign
/// allowlist contains only guards, so Type 3 stays behind typed APIs.
pub fn validate_raw_sign_transaction(
    transaction: &crate::tx_binding::CanonicalTransaction,
) -> WalletResult<()> {
    if transaction.tx_type == 3 {
        return Err(WalletError::Policy(
            "dapp_raw_type3_requires_typed_api: generic raw Type 3 signing is disabled until a reviewed non-guard leaf API is available".into(),
        ));
    }
    if transaction.tx_type != 2 {
        return Err(WalletError::Policy(format!(
            "dapp_raw_transaction_type_unsupported: generic raw signing allows Type 2 only, got Type {}",
            transaction.tx_type
        )));
    }
    if transaction.actions.is_empty() {
        return Err(WalletError::Policy(
            "raw dApp signing requires at least one reviewed action".into(),
        ));
    }
    // Harbor ownership challenges are safe only in their exact consensus-decoded
    // shape: one kind-14 action with from == to == transaction main address.
    if transaction.is_ownership_proof() {
        return Ok(());
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
    let intent = prepare_transfer_intent(&parsed)?;
    let mut summary = crate::tx_binding::describe_action_intents(&intent.actions)?;
    summary.push_str(&format!("\nTransaction type: {}", intent.tx_type));
    if let Some(gas_max) = intent.gas_max {
        summary.push_str(&format!("\nGas limit byte: {gas_max}"));
    }
    if let Some(chain_id) = intent.chain_id {
        summary.push_str(&format!("\nBound chain: {chain_id}"));
    }
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
    fn legacy_node_chain_status_does_not_claim_an_unknown_chain() {
        let status = chain_status_for_node(Some(0), None, "legacy_type2");
        assert!(status["current_chain_id"].is_null());
        assert_eq!(status["target_chain_id"], 0);
        assert_eq!(status["configured"], false);
        assert_eq!(status["matched"], false);
        assert_eq!(status["need_switch"], false);
        assert_eq!(status["capability_source"], "legacy_type2");
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
            gas_max: None,
            main_address: "wallet".into(),
            fee: "1:244".into(),
            body_sha256: "00".repeat(32),
            required_signers: vec![],
            signer_policy: crate::tx_binding::SignerPolicy::AtLeast,
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
    fn raw_sign_rejects_type3_even_with_reviewed_guard_kinds() {
        let mut transaction = canonical_with_kinds(&[0x0402, 0x0411]);
        transaction.tx_type = 3;
        transaction.gas_max = Some(17);
        let error = validate_raw_sign_transaction(&transaction).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("dapp_raw_type3_requires_typed_api")
        );
    }

    #[test]
    fn real_harbor_ownership_proof_is_the_only_kind14_raw_sign_exception() {
        const HARBOR_OWNERSHIP_PROOF_BODY: &str = "02006553f16300e63c33a796b3032ce6b856f68fccf06608d9ed18f401010001000e00e63c33a796b3032ce6b856f68fccf06608d9ed1800e63c33a796b3032ce6b856f68fccf06608d9ed18f0010100000000";

        crate::protocol_init::ensure_protocol_setup();
        let proof = crate::tx_binding::decode_transaction(HARBOR_OWNERSHIP_PROOF_BODY).unwrap();
        assert!(proof.is_ownership_proof());
        assert!(validate_raw_sign_transaction(&proof).is_ok());

        let other = "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW";
        let mut wrong_from = proof.clone();
        wrong_from.actions[0].canonical_json["from"] = json!(other);
        assert!(!wrong_from.is_ownership_proof());
        assert!(matches!(
            validate_raw_sign_transaction(&wrong_from),
            Err(WalletError::Policy(_))
        ));

        let mut wrong_to = proof.clone();
        wrong_to.actions[0].canonical_json["to"] = json!(other);
        assert!(!wrong_to.is_ownership_proof());
        assert!(matches!(
            validate_raw_sign_transaction(&wrong_to),
            Err(WalletError::Policy(_))
        ));

        let mut wrong_main = proof;
        wrong_main.main_address = other.into();
        assert!(!wrong_main.is_ownership_proof());
        assert!(matches!(
            validate_raw_sign_transaction(&wrong_main),
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

    #[test]
    fn transfer_intent_preserves_type3_gas_and_binds_chain() {
        let intent = prepare_transfer_intent(&json!({
            "tx_type": 3,
            "gas_max": 17,
            "chain_id": 0,
            "actions": [{
                "kind": 1,
                "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                "hacash": "1"
            }]
        }))
        .unwrap();
        assert_eq!(intent.tx_type, 3);
        assert_eq!(intent.gas_max, Some(17));
        assert_eq!(intent.chain_id, Some(0));
        assert_eq!(intent.actions[0], json!({ "kind": 0x0411, "chains": [0] }));
    }

    #[test]
    fn transfer_intent_rejects_silent_transaction_field_changes() {
        for request in [
            json!({
                "tx_type": 2, "gas_max": 0,
                "actions": [{ "kind": 1, "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", "hacash": "1" }]
            }),
            json!({
                "tx_type": 2, "type": 3,
                "actions": [{ "kind": 1, "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", "hacash": "1" }]
            }),
            json!({
                "tx_type": 4,
                "actions": [{ "kind": 1, "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", "hacash": "1" }]
            }),
            json!({
                "tx_type": 3, "gas_max": 17,
                "actions": [{ "kind": 1, "to": "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", "hacash": "1" }]
            }),
        ] {
            assert!(prepare_transfer_intent(&request).is_err());
        }
    }

    #[test]
    fn legacy_capability_fallback_allows_only_unbound_type2() {
        let capabilities = NodeCapabilities::legacy_type2("legacy");
        let plain = DappTransferIntent {
            tx_type: 2,
            gas_max: None,
            chain_id: None,
            actions: vec![json!({ "kind": 1 })],
        };
        assert!(validate_transfer_capabilities(&plain, &capabilities).is_ok());

        let mut type3 = plain.clone();
        type3.tx_type = 3;
        type3.gas_max = Some(0);
        assert!(validate_transfer_capabilities(&type3, &capabilities).is_err());

        let mut bound = plain;
        bound.chain_id = Some(0);
        assert!(validate_transfer_capabilities(&bound, &capabilities).is_err());
    }
}
