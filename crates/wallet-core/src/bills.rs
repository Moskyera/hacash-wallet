use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::paths::secure_write;

/// Encrypted-at-rest L2 settlement bill backup (dispute proofs).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BillStore {
    bills: HashMap<String, String>,
}

impl BillStore {
    pub fn load() -> WalletResult<Self> {
        let path = bills_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path).map_err(|e| WalletError::L2(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| WalletError::L2(e.to_string()))
    }

    pub fn save(&self) -> WalletResult<()> {
        let path = bills_path();
        let json = serde_json::to_string(self).map_err(|e| WalletError::L2(e.to_string()))?;
        secure_write(&path, json.as_bytes()).map_err(|e| WalletError::L2(e.to_string()))
    }

    pub fn store_bill(&mut self, payment_id: &str, bill_hex: &str) -> WalletResult<()> {
        self.bills.insert(payment_id.to_owned(), bill_hex.to_owned());
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