//! MoneyNex-compatible dApp bridge for HACD Launchpad (hacd.it).

use std::collections::HashSet;

use base64::Engine;
use serde_json::{Value, json};

use crate::error::{WalletError, WalletResult};
use crate::hip23::wire_mei_for_node;
use crate::l1_fee::{
    L1_DEFAULT_WIRE_BYTES, L1_PROBE_FEE_WIRE, estimate_l1_fee, signed_l1_wire_bytes,
};

#[allow(dead_code)]
const TRUSTED_HOSTS: &[&str] = &[
    "hacd.it",
    "www.hacd.it",
    // Harbor marketplace (local testnet UI. 8788 avoids DUST relay on 8787)
    "127.0.0.1:8787",
    "localhost:8787",
    "127.0.0.1:8788",
    "localhost:8788",
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

    let host = parsed.host_str()?;
    let trusted = match (parsed.scheme(), host) {
        ("https", "hacd.it" | "www.hacd.it") => {
            parsed.port().is_none() || parsed.port() == Some(443)
        }
        ("http", "127.0.0.1" | "localhost") => matches!(parsed.port(), Some(8787 | 8788)),
        _ => false,
    };
    if !trusted {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

pub fn origin_host_allowed(origin: &str) -> bool {
    normalized_trusted_origin(origin).is_some()
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
    let b64 = decode_uri_component(trimmed)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| WalletError::Transaction(format!("txobj base64: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| WalletError::Transaction(format!("txobj json: {e}")))
}

pub(crate) fn normalize_actions(actions: &[Value]) -> WalletResult<Vec<Value>> {
    let mut out = Vec::with_capacity(actions.len());
    for action in actions {
        let kind = action
            .get("kind")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| WalletError::Transaction("action missing kind".into()))?;
        let mut normalized = action.clone();
        match kind {
            1 => {
                if normalized.get("hacash").is_none() {
                    if let Some(amount) = action.get("amount").cloned() {
                        normalized["hacash"] = amount;
                    }
                }
            }
            6 => {
                normalized["kind"] = json!(5);
                if normalized.get("diamond").is_none() {
                    if let Some(d) = action.get("diamonds").and_then(|v| v.as_str()) {
                        normalized["diamond"] = json!(d);
                    }
                }
            }
            5 | 7 | 8 | 32 => {}
            _ => {}
        }
        out.push(normalized);
    }
    Ok(out)
}

/// Add wallet revenue actions at the intent layer before fee estimation,
/// transaction construction and approval binding.
pub(crate) fn append_mandatory_wallet_fee(actions: &mut Vec<Value>) -> WalletResult<()> {
    let mut hac_mei = 0.0f64;
    let mut satoshi = 0u64;
    for action in actions.iter() {
        match action.get("kind").and_then(Value::as_u64) {
            Some(1) => {
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
            Some(10) => {
                satoshi = satoshi
                    .checked_add(action.get("satoshi").and_then(Value::as_u64).ok_or_else(
                        || WalletError::Transaction("BTC action missing satoshi".into()),
                    )?)
                    .ok_or_else(|| WalletError::Transaction("BTC action amount overflow".into()))?;
            }
            _ => {}
        }
    }
    if hac_mei > 0.0 {
        actions.push(json!({
            "kind": 1,
            "to": crate::send_options::WALLET_TREASURY_ADDRESS,
            "hacash": crate::send_options::format_service_fee_amount_wire(
                crate::send_options::compute_service_fee_mei(hac_mei)
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
    if hac_mei == 0.0 && satoshi == 0 {
        actions.push(json!({
            "kind": 1,
            "to": crate::send_options::WALLET_TREASURY_ADDRESS,
            "hacash": crate::send_options::format_service_fee_amount_wire(
                crate::send_options::HACD_SERVICE_FEE_MEI
            )
        }));
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
    if let Some(fee) = payload.get("fee").and_then(|v| v.as_str()) {
        if !fee.is_empty() {
            return Ok(wire_mei_for_node(fee));
        }
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
        assert!(origin_host_allowed("https://www.hacd.it/"));
        assert!(origin_host_allowed("http://localhost:8788"));
        assert!(!origin_host_allowed("http://hacd.it"));
        assert!(!origin_host_allowed("https://evil.hacd.it"));
        assert!(!origin_host_allowed("https://hacd.it.evil.example"));
        assert!(!origin_host_allowed("https://hacd.it@evil.example"));
        assert!(!origin_host_allowed("https://hacd.it/launchpad"));
    }

    #[test]
    fn session_uses_canonical_origin() {
        let mut session = DappSession::new();
        session.authorize("https://hacd.it:443");
        assert!(session.is_authorized("https://hacd.it"));
        assert!(!session.is_authorized("https://www.hacd.it"));
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
}
