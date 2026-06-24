use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};
use crate::paths::secure_write;
use crate::payment::PaymentRail;

const MAX_RECORDS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub tx_hash: String,
    pub rail: String,
    pub from: String,
    pub to: String,
    pub amount_mei: f64,
    pub summary: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TxHistory {
    records: Vec<TxRecord>,
}

impl TxHistory {
    pub fn load() -> WalletResult<Self> {
        let path = history_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(&path).map_err(|e| WalletError::Other(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn save(&self) -> WalletResult<()> {
        let path = history_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| WalletError::Other(e.to_string()))?;
        }
        let json = serde_json::to_string(self).map_err(|e| WalletError::Other(e.to_string()))?;
        secure_write(&path, json.as_bytes()).map_err(|e| WalletError::Other(e.to_string()))
    }

    pub fn append(
        &mut self,
        rail: PaymentRail,
        tx_hash: &str,
        from: &str,
        to: &str,
        amount_mei: f64,
        summary: &str,
    ) -> WalletResult<()> {
        self.records.insert(
            0,
            TxRecord {
                tx_hash: tx_hash.to_owned(),
                rail: match rail {
                    PaymentRail::L2Fast => "L2Fast".into(),
                    PaymentRail::L1OnChain => "L1OnChain".into(),
                },
                from: from.to_owned(),
                to: to.to_owned(),
                amount_mei,
                summary: summary.to_owned(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
        );
        if self.records.len() > MAX_RECORDS {
            self.records.truncate(MAX_RECORDS);
        }
        self.save()
    }

    pub fn list(&self) -> &[TxRecord] {
        &self.records
    }
}

pub fn history_path() -> PathBuf {
    crate::paths::history_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_prepends_newest() {
        let mut h = TxHistory::default();
        h.append(
            PaymentRail::L1OnChain,
            "abc",
            "1From",
            "1To",
            1.0,
            "test",
        )
        .unwrap();
        assert_eq!(h.list()[0].tx_hash, "abc");
    }
}