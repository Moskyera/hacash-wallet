use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::paths::secure_write;

/// Private-permission L2 settlement bill backup (dispute proofs).
///
/// The document contains no blockchain private key, but it is not encrypted by
/// this type. Callers that require encrypted-at-rest metadata must place it in
/// an encrypted outer store rather than inferring encryption from `secure_write`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillStore {
    /// Storage ownership is runtime state, not part of the portable bill
    /// document. Deserialized legacy documents retain the Personal Wallet path;
    /// `load_at` replaces it with the exact caller-selected path.
    #[serde(skip, default = "bills_path")]
    path: PathBuf,
    bills: HashMap<String, String>,
}

impl Default for BillStore {
    fn default() -> Self {
        Self {
            path: bills_path(),
            bills: HashMap::new(),
        }
    }
}

impl BillStore {
    /// Load the Personal Wallet bill store from its historical location.
    ///
    /// Keeping this as a thin wrapper preserves the existing on-disk contract
    /// while allowing other wallet spaces to select an independent path.
    pub fn load() -> WalletResult<Self> {
        Self::load_at(bills_path())
    }

    /// Load a bill store permanently bound to `path`.
    ///
    /// A missing file creates an empty store that remains bound to this exact
    /// path. `save` never falls back to the Personal Wallet location.
    pub fn load_at(path: impl Into<PathBuf>) -> WalletResult<Self> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self {
                path,
                bills: HashMap::new(),
            });
        }
        let raw = fs::read_to_string(&path).map_err(|e| WalletError::L2(e.to_string()))?;
        let mut store: Self =
            serde_json::from_str(&raw).map_err(|e| WalletError::L2(e.to_string()))?;
        store.path = path;
        Ok(store)
    }

    pub fn save(&self) -> WalletResult<()> {
        let json = serde_json::to_string(self).map_err(|e| WalletError::L2(e.to_string()))?;
        secure_write(&self.path, json.as_bytes()).map_err(|e| WalletError::L2(e.to_string()))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn store_bill(&mut self, payment_id: &str, bill_hex: &str) -> WalletResult<()> {
        self.bills
            .insert(payment_id.to_owned(), bill_hex.to_owned());
        self.save()
    }

    pub fn get_bill(&self, payment_id: &str) -> Option<&str> {
        self.bills.get(payment_id).map(|s| s.as_str())
    }

    pub fn count(&self) -> usize {
        self.bills.len()
    }

    pub fn list(&self) -> Vec<BillEntry> {
        let mut out: Vec<BillEntry> = self
            .bills
            .iter()
            .map(|(id, hex)| BillEntry {
                payment_id: id.clone(),
                bill_hex: hex.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.payment_id.cmp(&b.payment_id));
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillEntry {
    pub payment_id: String,
    pub bill_hex: String,
}

pub fn bills_path() -> PathBuf {
    crate::paths::bills_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_at_different_paths_cannot_read_or_write_each_other() {
        let root = tempfile::tempdir().unwrap();
        let first_path = root.path().join("first").join("bills.json");
        let second_path = root.path().join("second").join("bills.json");

        let mut first = BillStore::load_at(&first_path).unwrap();
        first.store_bill("payment-first", "aa").unwrap();

        let second_before_write = BillStore::load_at(&second_path).unwrap();
        assert_eq!(second_before_write.count(), 0);
        assert!(second_before_write.get_bill("payment-first").is_none());
        assert!(!second_path.exists());

        let mut second = second_before_write;
        second.store_bill("payment-second", "bb").unwrap();

        let first_reloaded = BillStore::load_at(&first_path).unwrap();
        let second_reloaded = BillStore::load_at(&second_path).unwrap();
        assert_eq!(first_reloaded.path(), first_path);
        assert_eq!(second_reloaded.path(), second_path);
        assert_eq!(first_reloaded.get_bill("payment-first"), Some("aa"));
        assert!(first_reloaded.get_bill("payment-second").is_none());
        assert_eq!(second_reloaded.get_bill("payment-second"), Some("bb"));
        assert!(second_reloaded.get_bill("payment-first").is_none());
    }

    #[test]
    fn personal_default_and_legacy_document_keep_the_historical_path() {
        let personal_path = bills_path();
        let store = BillStore::default();
        assert_eq!(store.path(), personal_path);

        let encoded = serde_json::to_string(&store).unwrap();
        assert!(!encoded.contains(personal_path.to_string_lossy().as_ref()));
        let decoded: BillStore = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.path(), personal_path);
    }

    #[test]
    fn corrupt_store_never_falls_back_to_an_empty_store() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("bills.json");
        std::fs::write(&path, b"{not-valid-json").unwrap();
        assert!(BillStore::load_at(path).is_err());
    }
}
