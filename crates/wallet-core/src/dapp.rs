//! MoneyNex-compatible dApp bridge for HACD Launchpad (hacd.it).

use std::collections::HashSet;

use base64::Engine;
use serde_json::{json, Value};

use crate::error::{WalletError, WalletResult};
use crate::hip23::wire_mei_for_node;
use crate::l1_fee::{estimate_l1_fee, L1_DEFAULT_WIRE_BYTES, L1_PROBE_FEE_WIRE};


const TRUSTED_HOSTS: &[&str] = &["hacd.it", "www.hacd.it"];

pub fn origin_host_allowed(origin: &str) -> bool {
    let host = origin
        .trim()
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(origin);
    TRUSTED_HOSTS.iter().any(|h| host == *h || host.ends_with(&format!(".{h}")))
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
            return estimate_l1_fee(node, L1_DEFAULT_WIRE_BYTES, crate::send_options::L1FeeSpeed::Normal)
                .await
                .map(|e| e.fee_wire);
        }
    };
    let wire_bytes = if built.ret == 0 {
        built
            .body
            .as_ref()
            .map(|b| (b.len() / 2).max(1))
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
        if origin_host_allowed(origin) {
            self.authorized_origins.insert(origin.to_string());
        }
    }

    pub fn is_authorized(&self, origin: &str) -> bool {
        self.authorized_origins.contains(origin)
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