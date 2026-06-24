use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

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
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| WalletError::L2(e.to_string()))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| WalletError::L2(e.to_string()))?;
        fs::write(path, json).map_err(|e| WalletError::L2(e.to_string()))
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
}

pub fn bills_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("HacashWallet")
        .join("l2_bills.json")
}