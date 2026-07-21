use sdk::{
    HybridAccountInfo as SdkInfo, create_hybrid_account_keystore, create_pqc_account_keystore,
    export_hybrid_keystore, keystore_unlock_blob, unlock_hybrid_keystore,
};
use serde::{Deserialize, Serialize};
use sys::Account;

use crate::error::{WalletError, WalletResult};
use crate::wallet::WalletService;

/// Placeholder fee for unsigned body sizing only.
const TYPE4_PROBE_FEE_WIRE: &str = "0:001";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuantumAccountSummary {
    pub kind: String,
    pub address: String,
    pub address_version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSettings {
    pub quantum_mode: bool,
    #[serde(default)]
    pub active_account: Option<QuantumAccountSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumPreflight {
    pub ok: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub balance_mei: f64,
    pub fee_wire: String,
    pub fee_mei: f64,
    pub service_fee_mei: f64,
    pub service_fee_treasury: String,
    pub total_mei: f64,
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

fn summary_from_resolved(
    kind: String,
    address: String,
    address_version: u8,
) -> QuantumAccountSummary {
    QuantumAccountSummary {
        kind,
        address,
        address_version,
    }
}

pub fn quantum_meta_from_json(json: &str) -> Option<crate::settings::QuantumMeta> {
    let (addr, kind) = parse_keystore_meta(json);
    let (resolved_kind, version) = resolve_quantum_meta(kind.as_deref(), addr.as_deref());
    let address = addr?;
    let kind = resolved_kind?;
    let version = version?;
    Some(crate::settings::QuantumMeta {
        address,
        kind,
        address_version: version,
    })
}

fn parse_decimal_hac_mei(amount: &str) -> WalletResult<f64> {
    let v: f64 = amount
        .trim()
        .parse()
        .map_err(|_| WalletError::Other(format!("invalid HAC amount: {amount}")))?;
    crate::hip23::validate_hac_amount_mei(v)?;
    Ok(v)
}

pub fn build_type4_unsigned_body(
    from_address: &str,
    to_address: &str,
    amount_hacash: &str,
    fee_wire: &str,
) -> WalletResult<String> {
    build_type4_unsigned_body_transfers(from_address, fee_wire, &[(to_address, amount_hacash)])
}

pub fn build_type4_unsigned_body_transfers(
    from_address: &str,
    fee_wire: &str,
    transfers: &[(&str, &str)],
) -> WalletResult<String> {
    use basis::interface::Transaction;
    use field::{Address, Amount, Serialize, Uint1};
    use protocol::action::HacToTrs;
    use protocol::transaction::TransactionType4;
    use sys::{ToHex, curtimes};

    let mainaddr = Address::from_readable(from_address)
        .map_err(|e| WalletError::Other(format!("address invalid: {e}")))?;
    if !mainaddr.is_pqckey() && !mainaddr.is_hybrid() {
        return Err(WalletError::Other(
            "type 4 sender must be a PQC or Hybrid address".into(),
        ));
    }
    let fee =
        Amount::from(fee_wire).map_err(|e| WalletError::Other(format!("fee invalid: {e}")))?;
    let ts = curtimes();
    let mut tx = TransactionType4::new_by(mainaddr, fee, ts);
    tx.gas_max = Uint1::from(0u8);
    for (to_address, amount_hacash) in transfers {
        let toaddr = Address::from_readable(to_address)
            .map_err(|e| WalletError::Other(format!("recipient invalid: {e}")))?;
        let hac = Amount::from(amount_hacash)
            .map_err(|e| WalletError::Other(format!("hacash invalid: {e}")))?;
        tx.push_action(Box::new(HacToTrs::create_by(toaddr, hac)))
            .map_err(|e| WalletError::Other(e.to_string()))?;
    }
    Ok(tx.serialize().to_hex())
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

/// CPU-heavy keystore creation. run off the wallet mutex (e.g. `spawn_blocking`).
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

pub fn import_keystore_offline(
    json: &str,
    pass: &str,
) -> WalletResult<(String, QuantumAccountInfo)> {
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
        let active_account = self
            .quantum_meta_snapshot()
            .as_ref()
            .map(|m| summary_from_resolved(m.kind.clone(), m.address.clone(), m.address_version))
            .or_else(|| {
                let json = self.quantum_keystore_json();
                let (active, kind) = json
                    .as_deref()
                    .map(parse_keystore_meta)
                    .unwrap_or((None, None));
                let (resolved_kind, version) =
                    resolve_quantum_meta(kind.as_deref(), active.as_deref());
                match (resolved_kind, active, version) {
                    (Some(k), Some(a), Some(v)) => Some(summary_from_resolved(k, a, v)),
                    _ => None,
                }
            });
        QuantumSettings {
            quantum_mode: self.quantum_mode_enabled(),
            active_account,
        }
    }

    pub async fn quantum_balance_mei(&self) -> WalletResult<f64> {
        let settings = self.quantum_settings();
        let addr = settings
            .active_account
            .as_ref()
            .map(|a| a.address.as_str())
            .ok_or_else(|| WalletError::Other("no quantum account".into()))?;
        self.node_client().balance_mei(addr).await
    }

    pub async fn quantum_preflight_type4(
        &self,
        to: &str,
        amount_hacash: &str,
    ) -> WalletResult<QuantumPreflight> {
        self.require_quantum_testnet()?;
        let settings = self.quantum_settings();
        let account = settings
            .active_account
            .as_ref()
            .ok_or_else(|| WalletError::Other("no quantum account".into()))?;
        let amount_mei = parse_decimal_hac_mei(amount_hacash)?;
        let service_fee_mei = crate::send_options::compute_service_fee_mei(amount_mei);
        let balance_mei = self.quantum_balance_mei().await?;
        let fee_est = self
            .estimate_type4_fee(&account.address, to, amount_hacash, None)
            .await?;
        let check = crate::hip23::validate_type4_send(
            &account.kind,
            to,
            amount_mei + service_fee_mei,
            balance_mei,
            &fee_est.fee_wire,
        )?;
        Ok(QuantumPreflight {
            ok: check.ok,
            warnings: check.warnings,
            errors: check.errors,
            balance_mei,
            fee_wire: fee_est.fee_wire,
            fee_mei: fee_est.fee_mei,
            service_fee_mei,
            service_fee_treasury: crate::send_options::WALLET_TREASURY_ADDRESS.into(),
            total_mei: amount_mei + service_fee_mei + fee_est.fee_mei,
        })
    }

    async fn estimate_type4_fee(
        &self,
        from_address: &str,
        to: &str,
        amount_hacash: &str,
        keystore_pass: Option<&str>,
    ) -> WalletResult<crate::type4_fee::Type4FeeEstimate> {
        use crate::type4_fee::{
            estimate_signed_wire_bytes, fee_from_node_average, local_fee_from_wire_bytes,
        };

        let amount_mei = parse_decimal_hac_mei(amount_hacash)?;
        let amount_wire = crate::hip23::format_mei_for_node(amount_mei);
        let service_fee_wire = crate::send_options::format_service_fee_amount_wire(
            crate::send_options::compute_service_fee_mei(amount_mei),
        );
        let unsigned = build_type4_unsigned_body_transfers(
            from_address,
            TYPE4_PROBE_FEE_WIRE,
            &[
                (to, amount_wire.as_str()),
                (
                    crate::send_options::WALLET_TREASURY_ADDRESS,
                    service_fee_wire.as_str(),
                ),
            ],
        )?;
        let wire_bytes = if let Some(pass) = keystore_pass {
            let ks = self.require_keystore_json()?;
            let param = sdk::SignTxV4Param {
                body: unsigned,
                hybrid_keystore: ks,
                keystore_pass: pass.into(),
            };
            let built = tokio::task::spawn_blocking(move || {
                sdk::sign_transaction_v4(param).map_err(WalletError::Other)
            })
            .await
            .map_err(|e| WalletError::Other(format!("type 4 fee probe failed: {e}")))??;
            built.body.len() / 2
        } else {
            estimate_signed_wire_bytes(unsigned.len() / 2)
        };

        match self.node_client().query_fee_average(wire_bytes, 4).await {
            Ok(resp) => fee_from_node_average(&resp.feasible, wire_bytes, resp.purity),
            Err(_) => Ok(local_fee_from_wire_bytes(wire_bytes)),
        }
    }

    pub fn set_quantum_mode(&mut self, enabled: bool) -> WalletResult<()> {
        self.set_quantum_mode_flag(enabled)
    }

    fn require_keystore_json(&self) -> WalletResult<String> {
        self.quantum_keystore_json()
            .ok_or_else(|| WalletError::Other("no quantum keystore. create or import first".into()))
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

    pub fn quantum_import_keystore(
        &mut self,
        json: &str,
        pass: &str,
    ) -> WalletResult<QuantumAccountInfo> {
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
        self.require_quantum_testnet()?;
        let amount_mei = parse_decimal_hac_mei(amount)?;
        self.ensure_quantum_signing_policy(amount_mei)?;
        let settings = self.quantum_settings();
        let from = settings
            .active_account
            .as_ref()
            .ok_or_else(|| WalletError::Other("no quantum account".into()))?;
        let service_fee_mei = crate::send_options::compute_service_fee_mei(amount_mei);
        let balance_mei = self.quantum_balance_mei().await?;
        let fee_est = self
            .estimate_type4_fee(&from.address, to, amount, Some(keystore_pass))
            .await?;
        let check = crate::hip23::validate_type4_send(
            &from.kind,
            to,
            amount_mei + service_fee_mei,
            balance_mei,
            &fee_est.fee_wire,
        )?;
        if !check.ok {
            return Err(WalletError::Policy(check.errors.join("; ")));
        }
        let amount_wire = crate::hip23::format_mei_for_node(amount_mei);
        let service_fee_wire = crate::send_options::format_service_fee_amount_wire(service_fee_mei);
        let unsigned = build_type4_unsigned_body_transfers(
            &from.address,
            &fee_est.fee_wire,
            &[
                (to, amount_wire.as_str()),
                (
                    crate::send_options::WALLET_TREASURY_ADDRESS,
                    service_fee_wire.as_str(),
                ),
            ],
        )?;
        crate::tx_binding::verify_hac_transfers(
            &unsigned,
            &from.address,
            &fee_est.fee_wire,
            &[
                (to, amount_wire.as_str()),
                (
                    crate::send_options::WALLET_TREASURY_ADDRESS,
                    service_fee_wire.as_str(),
                ),
            ],
        )?;
        self.ensure_transaction_network_binding(&unsigned).await?;
        let param = sdk::SignTxV4Param {
            body: unsigned,
            hybrid_keystore: self.require_keystore_json()?,
            keystore_pass: keystore_pass.into(),
        };
        // PQC signing is stack-heavy; avoid running on the small async worker stack (debug builds).
        let built = tokio::task::spawn_blocking(move || {
            sdk::sign_transaction_v4(param).map_err(WalletError::Other)
        })
        .await
        .map_err(|e| WalletError::Other(format!("type 4 sign task failed: {e}")))?;
        let built = built?;
        self.clear_second_factor();
        let wire_size = built.body.len() / 2;
        let submitted = self.submit_signed_tx(&built.body).await?;
        let hash = submitted
            .hash
            .ok_or_else(|| WalletError::Transaction("missing tx hash".into()))?;
        let result = QuantumSendResult {
            hash: hash.clone(),
            tx_type: 4,
            sign_alg: built.sign_alg,
            wire_size,
            fee_used: fee_est.fee_wire,
        };
        let _ = self.append_quantum_history(
            &hash,
            &from.address,
            to,
            amount_mei,
            "Type 4 quantum transfer",
        );
        Ok(result)
    }

    pub async fn prepare_airgap_type4(
        &mut self,
        to: &str,
        amount_hacash: &str,
    ) -> WalletResult<crate::airgap::AirgapPrepareResult> {
        self.touch_auto_lock();
        self.require_quantum_testnet()?;
        let settings = self.quantum_settings();
        let from = settings
            .active_account
            .as_ref()
            .ok_or_else(|| WalletError::Other("no quantum account".into()))?;
        let requested_amount = parse_decimal_hac_mei(amount_hacash)?;
        let amount = crate::airgap::canonicalize_airgap_amount(requested_amount)?;
        let preflight = self
            .quantum_preflight_type4(to, &amount.amount_wire)
            .await?;
        if !preflight.ok {
            return Err(WalletError::Policy(preflight.errors.join("; ")));
        }
        let fee_est = self
            .estimate_type4_fee(&from.address, to, &amount.amount_wire, None)
            .await?;
        let service_fee_wire =
            crate::send_options::format_service_fee_amount_wire(preflight.service_fee_mei);
        let body_hex = build_type4_unsigned_body_transfers(
            &from.address,
            &fee_est.fee_wire,
            &[
                (to, amount.amount_wire.as_str()),
                (
                    crate::send_options::WALLET_TREASURY_ADDRESS,
                    service_fee_wire.as_str(),
                ),
            ],
        )?;
        let summary = crate::airgap::canonical_airgap_summary(4, to, &amount.amount_wire)?;
        let unsigned = crate::airgap::AirgapUnsigned {
            v: crate::airgap::AIRGAP_VERSION,
            from: from.address.clone(),
            to: to.to_owned(),
            amount_mei: amount.amount_mei,
            amount_wire: amount.amount_wire,
            fee: fee_est.fee_wire,
            service_fee_mei: preflight.service_fee_mei,
            service_fee_treasury: Some(crate::send_options::WALLET_TREASURY_ADDRESS.into()),
            body_hex,
            summary,
            tx_type: 4,
        };
        let qr_parts = crate::airgap::encode_envelope_qr(
            &crate::airgap::AirgapEnvelope::Unsigned(unsigned.clone()),
        )?;
        let inspection = self
            .inspect_airgap_envelope(&crate::airgap::AirgapEnvelope::Unsigned(unsigned.clone()))?;
        Ok(crate::airgap::AirgapPrepareResult {
            envelope: unsigned,
            inspection,
            qr_parts,
        })
    }

    pub fn quantum_airgap_sign_type4(
        &mut self,
        unsigned: &crate::airgap::AirgapUnsigned,
        keystore_pass: &str,
    ) -> WalletResult<crate::airgap::AirgapSignResult> {
        self.touch_auto_lock();
        self.require_quantum_testnet()?;
        let inspection = self
            .inspect_airgap_envelope(&crate::airgap::AirgapEnvelope::Unsigned(unsigned.clone()))?;
        if inspection.tx_type != 4 {
            return Err(WalletError::Policy(
                "air-gap sign expects Type 4 unsigned envelope".into(),
            ));
        }
        self.ensure_quantum_signing_policy(inspection.amount_mei)?;
        if unsigned.from.is_empty() || unsigned.to.is_empty() {
            return Err(WalletError::Transaction(
                "airgap unsigned missing addresses".into(),
            ));
        }
        let expected_addr = self
            .quantum_settings()
            .active_account
            .as_ref()
            .ok_or_else(|| WalletError::Other("no quantum account".into()))?
            .address
            .clone();
        if unsigned.from != expected_addr {
            return Err(WalletError::Policy(format!(
                "offline signer quantum address {expected_addr} does not match unsigned tx from {}",
                unsigned.from
            )));
        }
        let expected_service_fee =
            crate::send_options::compute_service_fee_mei(inspection.amount_mei);
        if (unsigned.service_fee_mei - expected_service_fee).abs() > 0.000_000_1
            || unsigned.service_fee_treasury.as_deref()
                != Some(crate::send_options::WALLET_TREASURY_ADDRESS)
        {
            return Err(WalletError::Policy(
                "air-gap Type 4 envelope has a missing or incorrect wallet fee".into(),
            ));
        }
        let service_fee_wire =
            crate::send_options::format_service_fee_amount_wire(expected_service_fee);
        crate::tx_binding::verify_hac_transfers(
            &unsigned.body_hex,
            &unsigned.from,
            &unsigned.fee,
            &[
                (unsigned.to.as_str(), unsigned.amount_wire.as_str()),
                (
                    crate::send_options::WALLET_TREASURY_ADDRESS,
                    service_fee_wire.as_str(),
                ),
            ],
        )?;
        use sdk::SignTxV4Param;
        use sdk::sign_transaction_v4;
        let signed = sign_transaction_v4(SignTxV4Param {
            body: unsigned.body_hex.clone(),
            hybrid_keystore: self.require_keystore_json()?,
            keystore_pass: keystore_pass.into(),
        })
        .map_err(WalletError::Other)?;
        self.clear_second_factor();
        let envelope = crate::airgap::AirgapSigned {
            v: crate::airgap::AIRGAP_VERSION,
            from: inspection.from,
            to: inspection.to,
            amount_mei: inspection.amount_mei,
            amount_wire: inspection.amount_wire,
            fee: inspection.network_fee,
            service_fee_mei: inspection.wallet_fee_mei,
            service_fee_treasury: Some(inspection.wallet_fee_treasury),
            signed_hex: signed.body,
            summary: inspection.summary,
            tx_type: 4,
        };
        let qr_parts = crate::airgap::encode_envelope_qr(&crate::airgap::AirgapEnvelope::Signed(
            envelope.clone(),
        ))?;
        let inspection =
            self.inspect_airgap_envelope(&crate::airgap::AirgapEnvelope::Signed(envelope.clone()))?;
        Ok(crate::airgap::AirgapSignResult {
            envelope,
            inspection,
            qr_parts,
        })
    }

    pub async fn quantum_send_test_tx(
        &mut self,
        _keystore_pass: &str,
    ) -> WalletResult<QuantumTestResult> {
        Err(WalletError::Policy(
            "Unsafe one-click test transfer was removed; use preflight or node diagnostics".into(),
        ))
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
        assert_eq!(version_from_address_readable(&created.address), Some(6));

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
        assert_eq!(version_from_address_readable(&created.address), Some(7));

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
