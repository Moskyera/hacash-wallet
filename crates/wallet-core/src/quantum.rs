use serde::{Deserialize, Serialize};
use sdk::{
    create_coin_transfer_v4, create_hybrid_account_keystore, create_pqc_account_keystore,
    export_hybrid_keystore, keystore_unlock_blob, unlock_hybrid_keystore, CoinTransferV4Param,
    HybridAccountInfo as SdkInfo,
};
use sys::Account;

use crate::error::{WalletError, WalletResult};
use crate::wallet::WalletService;

pub const TYPE4_AUTO_FEE: &str = "40:244";
pub const TEST_LEGACY_RECIPIENT: &str = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSettings {
    pub quantum_mode: bool,
    pub active_address: Option<String>,
    pub address_version: Option<u8>,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumAccountInfo {
    pub kind: String,
    pub address: String,
    pub address_version: u8,
    pub alg_id: u8,
    pub mldsa_pubkey: String,
    pub secp_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSendResult {
    pub hash: String,
    pub tx_type: u8,
    pub sign_alg: u8,
    pub wire_size: usize,
    pub fee_used: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumTestResult {
    pub hash: String,
    pub fee_used: String,
    pub metrics: serde_json::Value,
}

fn map_info(i: SdkInfo) -> QuantumAccountInfo {
    QuantumAccountInfo {
        kind: i.kind,
        address: i.address,
        address_version: i.address_version,
        alg_id: i.alg_id,
        mldsa_pubkey: i.mldsa_pubkey,
        secp_pubkey: i.secp_pubkey,
    }
}

fn parse_keystore_meta(json: &str) -> (Option<String>, Option<String>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return (None, None);
    };
    let addr = v.get("address").and_then(|a| a.as_str()).map(str::to_owned);
    let kind = v.get("kind").and_then(|k| k.as_str()).map(str::to_owned);
    (addr, kind)
}

/// Protocol address version: v6 = PQC (`pqckey`), v7 = hybrid (`hybrid`).
fn version_from_kind(kind: Option<&str>) -> Option<u8> {
    match kind {
        Some("hybrid") => Some(7),
        Some("pqckey") => Some(6),
        _ => None,
    }
}

fn kind_from_version(version: u8) -> Option<&'static str> {
    match version {
        6 => Some("pqckey"),
        7 => Some("hybrid"),
        _ => None,
    }
}

/// Decode version byte from base58check address (authoritative; no string-prefix guessing).
fn version_from_address_readable(addr: &str) -> Option<u8> {
    use field::Address;
    let v = Address::from_readable(addr).ok()?.version();
    match v {
        Address::PQCKEY | Address::HYBRID => Some(v),
        _ => None,
    }
}

/// Resolve `(kind, address_version)` once for settings/UI. On keystore/address disagreement,
/// the decoded address wins (on-chain identity is authoritative).
fn resolve_quantum_meta(kind: Option<&str>, address: Option<&str>) -> (Option<String>, Option<u8>) {
    let kind_version = version_from_kind(kind);
    let addr_version = address.and_then(version_from_address_readable);

    let version = match (kind_version, addr_version) {
        (Some(kv), Some(av)) if kv != av => Some(av),
        (Some(kv), _) => Some(kv),
        (None, Some(av)) => Some(av),
        (None, None) => None,
    };

    let resolved_kind = version.and_then(|v| kind_from_version(v).map(str::to_owned));
    (resolved_kind, version)
}

pub fn preview_keystore(json: &str, pass: &str) -> WalletResult<QuantumAccountInfo> {
    let info = unlock_hybrid_keystore(json, pass).map_err(WalletError::Other)?;
    Ok(map_info(info))
}

/// CPU-heavy keystore creation — run off the wallet mutex (e.g. `spawn_blocking`).
pub fn create_pqc_keystore_offline(pass: &str) -> WalletResult<(String, QuantumAccountInfo)> {
    let out = create_pqc_account_keystore(pass).map_err(WalletError::Other)?;
    Ok((out.keystore, map_info(out.info)))
}

pub fn create_hybrid_keystore_offline(
    pass: &str,
    legacy_prikey_hex: Option<&str>,
) -> WalletResult<(String, QuantumAccountInfo)> {
    let prikey = legacy_prikey_hex.unwrap_or("");
    let out = create_hybrid_account_keystore(pass, prikey).map_err(WalletError::Other)?;
    Ok((out.keystore, map_info(out.info)))
}

pub fn import_keystore_offline(json: &str, pass: &str) -> WalletResult<(String, QuantumAccountInfo)> {
    keystore_unlock_blob(json, pass).map_err(WalletError::Other)?;
    let info = unlock_hybrid_keystore(json, pass).map_err(WalletError::Other)?;
    Ok((json.to_owned(), map_info(info)))
}

pub fn create_hybrid_from_privakey_offline(
    legacy_prikey_hex: &str,
    pass: &str,
) -> WalletResult<(String, QuantumAccountInfo)> {
    Account::create_by(legacy_prikey_hex).map_err(WalletError::Other)?;
    create_hybrid_keystore_offline(pass, Some(legacy_prikey_hex))
}

impl WalletService {
    pub fn quantum_settings(&self) -> QuantumSettings {
        let json = self.quantum_keystore_json();
        let (active, kind) = json.as_deref().map(parse_keystore_meta).unwrap_or((None, None));
        let (resolved_kind, version) = resolve_quantum_meta(kind.as_deref(), active.as_deref());
        QuantumSettings {
            quantum_mode: self.quantum_mode_enabled(),
            active_address: active,
            address_version: version,
            kind: resolved_kind,
        }
    }

    pub fn set_quantum_mode(&mut self, enabled: bool) -> WalletResult<()> {
        self.set_quantum_mode_flag(enabled)
    }

    fn require_keystore_json(&self) -> WalletResult<String> {
        self.quantum_keystore_json()
            .ok_or_else(|| WalletError::Other("no quantum keystore — create or import first".into()))
    }

    pub fn quantum_create_pqc(&mut self, pass: &str) -> WalletResult<QuantumAccountInfo> {
        self.bump_unlock_activity();
        let (keystore, info) = create_pqc_keystore_offline(pass)?;
        self.store_quantum_keystore_json(keystore)?;
        Ok(info)
    }

    pub fn quantum_create_hybrid(
        &mut self,
        pass: &str,
        legacy_prikey_hex: Option<&str>,
    ) -> WalletResult<QuantumAccountInfo> {
        self.bump_unlock_activity();
        let (keystore, info) = create_hybrid_keystore_offline(pass, legacy_prikey_hex)?;
        self.store_quantum_keystore_json(keystore)?;
        Ok(info)
    }

    pub fn quantum_create_hybrid_from_privakey(
        &mut self,
        legacy_prikey_hex: &str,
        pass: &str,
    ) -> WalletResult<QuantumAccountInfo> {
        Account::create_by(legacy_prikey_hex).map_err(WalletError::Other)?;
        self.quantum_create_hybrid(pass, Some(legacy_prikey_hex))
    }

    pub fn quantum_import_keystore(&mut self, json: &str, pass: &str) -> WalletResult<QuantumAccountInfo> {
        self.bump_unlock_activity();
        let (keystore, info) = import_keystore_offline(json, pass)?;
        self.store_quantum_keystore_json(keystore)?;
        Ok(info)
    }

    pub fn quantum_export_keystore(
        &self,
        pass: &str,
        new_password: Option<&str>,
    ) -> WalletResult<String> {
        let json = self.require_keystore_json()?;
        keystore_unlock_blob(&json, pass).map_err(WalletError::Other)?;
        if let Some(np) = new_password {
            let exp = export_hybrid_keystore(&json, pass, np).map_err(WalletError::Other)?;
            return Ok(exp.json);
        }
        Ok(json)
    }

    pub async fn quantum_send_type4(
        &mut self,
        to: &str,
        amount: &str,
        keystore_pass: &str,
    ) -> WalletResult<QuantumSendResult> {
        self.touch_auto_lock();
        let ks = self.require_keystore_json()?;
        let built = create_coin_transfer_v4(CoinTransferV4Param {
            main_keystore: ks,
            keystore_pass: keystore_pass.into(),
            fee: TYPE4_AUTO_FEE.into(),
            to_address: to.into(),
            timestamp: 0,
            hacash: amount.into(),
            gas_max: 0,
        })
        .map_err(WalletError::Other)?;
        let wire_size = built.body.len() / 2;
        let submitted = self.node_client().submit_tx_hex_body(&built.body).await?;
        let hash = submitted
            .hash
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
        Ok(QuantumSendResult {
            hash,
            tx_type: 4,
            sign_alg: 3,
            wire_size,
            fee_used: TYPE4_AUTO_FEE.into(),
        })
    }

    pub async fn quantum_send_test_tx(&mut self, keystore_pass: &str) -> WalletResult<QuantumTestResult> {
        let send = self
            .quantum_send_type4(TEST_LEGACY_RECIPIENT, "0.1", keystore_pass)
            .await?;
        let metrics = self.quantum_node_metrics().await?;
        Ok(QuantumTestResult {
            hash: send.hash,
            fee_used: send.fee_used,
            metrics,
        })
    }

    pub async fn quantum_node_metrics(&self) -> WalletResult<serde_json::Value> {
        self.node_client().query_metrics().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_kind_maps_hybrid_and_pqc() {
        assert_eq!(version_from_kind(Some("hybrid")), Some(7));
        assert_eq!(version_from_kind(Some("pqckey")), Some(6));
        assert_eq!(version_from_kind(None), None);
        assert_eq!(version_from_kind(Some("legacy")), None);
    }

    #[test]
    fn create_pqc_keystore_unlock_roundtrip() {
        let pass = "quantum-unit-pqc-pass";
        let (json, created) = create_pqc_keystore_offline(pass).unwrap();
        assert_eq!(created.kind, "pqckey");
        assert_eq!(created.address_version, 6);
        assert_eq!(
            version_from_address_readable(&created.address),
            Some(6)
        );

        let preview = preview_keystore(&json, pass).unwrap();
        assert_eq!(preview.address, created.address);
        assert_eq!(preview.kind, "pqckey");
    }

    #[test]
    fn create_hybrid_keystore_unlock_roundtrip() {
        let pass = "quantum-unit-hybrid-pass";
        let (json, created) = create_hybrid_keystore_offline(pass, None).unwrap();
        assert_eq!(created.kind, "hybrid");
        assert_eq!(created.address_version, 7);
        assert_eq!(
            version_from_address_readable(&created.address),
            Some(7)
        );

        let preview = preview_keystore(&json, pass).unwrap();
        assert_eq!(preview.address, created.address);
        assert_eq!(preview.kind, "hybrid");
    }

    #[test]
    fn import_keystore_rejects_wrong_password() {
        let pass = "quantum-unit-import-pass";
        let (json, _) = create_pqc_keystore_offline(pass).unwrap();
        assert!(import_keystore_offline(&json, "wrong-password").is_err());
    }

    #[test]
    fn export_keystore_with_new_password_roundtrip() {
        let old_pass = "quantum-export-old";
        let new_pass = "quantum-export-new";
        let (json, info) = create_hybrid_keystore_offline(old_pass, None).unwrap();

        let exported = export_hybrid_keystore(&json, old_pass, new_pass)
            .map_err(WalletError::Other)
            .unwrap()
            .json;
        assert!(import_keystore_offline(&exported, new_pass).is_ok());
        let preview = preview_keystore(&exported, new_pass).unwrap();
        assert_eq!(preview.address, info.address);
        assert!(preview_keystore(&exported, old_pass).is_err());
    }

    #[test]
    fn pqc_and_hybrid_produce_distinct_v6_v7_addresses() {
        let (_, pqc) = create_pqc_keystore_offline("distinct-pqc-pass").unwrap();
        let (_, hybrid) = create_hybrid_keystore_offline("distinct-hyb-pass", None).unwrap();
        assert_eq!(pqc.address_version, 6);
        assert_eq!(hybrid.address_version, 7);
        assert_ne!(pqc.address, hybrid.address);
        let (pqc_kind, pqc_ver) = resolve_quantum_meta(Some("pqckey"), Some(&pqc.address));
        assert_eq!(pqc_ver, Some(6));
        assert_eq!(pqc_kind.as_deref(), Some("pqckey"));

        let (hyb_kind, hyb_ver) = resolve_quantum_meta(Some("hybrid"), Some(&hybrid.address));
        assert_eq!(hyb_ver, Some(7));
        assert_eq!(hyb_kind.as_deref(), Some("hybrid"));
    }

    #[test]
    fn resolve_quantum_meta_prefers_address_on_kind_mismatch() {
        let (_, pqc) = create_pqc_keystore_offline("mismatch-pass").unwrap();
        let (kind, ver) = resolve_quantum_meta(Some("hybrid"), Some(&pqc.address));
        assert_eq!(ver, Some(6));
        assert_eq!(kind.as_deref(), Some("pqckey"));
    }

    #[test]
    fn resolve_quantum_meta_backfills_kind_from_address() {
        let (_, hybrid) = create_hybrid_keystore_offline("backfill-pass", None).unwrap();
        let (kind, ver) = resolve_quantum_meta(None, Some(&hybrid.address));
        assert_eq!(ver, Some(7));
        assert_eq!(kind.as_deref(), Some("hybrid"));
    }
}