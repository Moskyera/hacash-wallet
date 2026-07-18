use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{WalletError, WalletResult};
use crate::paths::secure_write;
use crate::payment::PaymentRail;

const MAX_RECORDS: usize = 500;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TxStatus {
    #[default]
    Confirmed,
    Pending,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub tx_hash: String,
    pub rail: String,
    pub from: String,
    pub to: String,
    pub amount_mei: f64,
    pub summary: String,
    pub timestamp: String,
    #[serde(default)]
    pub status: TxStatus,
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
        self.append_with_status(
            rail,
            tx_hash,
            from,
            to,
            amount_mei,
            summary,
            TxStatus::Confirmed,
        )
    }

    // This stable API maps one-to-one to the persisted transaction record.
    #[allow(clippy::too_many_arguments)]
    pub fn append_with_status(
        &mut self,
        rail: PaymentRail,
        tx_hash: &str,
        from: &str,
        to: &str,
        amount_mei: f64,
        summary: &str,
        status: TxStatus,
    ) -> WalletResult<()> {
        self.records.insert(
            0,
            TxRecord {
                tx_hash: tx_hash.to_owned(),
                rail: rail_label(rail),
                from: from.to_owned(),
                to: to.to_owned(),
                amount_mei,
                summary: summary.to_owned(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                status,
            },
        );
        if self.records.len() > MAX_RECORDS {
            self.records.truncate(MAX_RECORDS);
        }
        self.save()
    }
    pub fn begin_pending(
        &mut self,
        rail: PaymentRail,
        from: &str,
        to: &str,
        amount_mei: f64,
    ) -> WalletResult<String> {
        let key = format!("pending:{}", Uuid::new_v4());
        self.append_with_status(
            rail,
            &key,
            from,
            to,
            amount_mei,
            "Sending…",
            TxStatus::Pending,
        )?;
        Ok(key)
    }

    pub fn resolve_pending(
        &mut self,
        pending_key: &str,
        tx_hash: &str,
        summary: &str,
        status: TxStatus,
    ) -> WalletResult<()> {
        let Some(rec) = self.records.iter_mut().find(|r| r.tx_hash == pending_key) else {
            return Ok(());
        };
        rec.tx_hash = tx_hash.to_owned();
        rec.summary = summary.to_owned();
        rec.status = status;
        self.save()
    }

    pub fn mark_failed(&mut self, pending_key: &str) -> WalletResult<()> {
        let Some(rec) = self.records.iter_mut().find(|r| r.tx_hash == pending_key) else {
            return Ok(());
        };
        rec.status = TxStatus::Failed;
        if rec.summary == "Sending…" {
            rec.summary = "Failed".into();
        }
        self.save()
    }

    pub fn list(&self) -> &[TxRecord] {
        &self.records
    }

    pub fn pending_fast_pay_records(&self) -> Vec<TxRecord> {
        self.records
            .iter()
            .filter(|record| {
                record.rail == "L2Fast"
                    && record.status == TxStatus::Pending
                    && !record.tx_hash.starts_with("pending:")
            })
            .cloned()
            .collect()
    }
}

fn rail_label(rail: PaymentRail) -> String {
    match rail {
        PaymentRail::L2Fast => "L2Fast".into(),
        PaymentRail::L1OnChain => "L1OnChain".into(),
        PaymentRail::QuantumType4 => "QuantumType4".into(),
    }
}

pub fn history_path() -> PathBuf {
    crate::paths::history_path()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::IsolatedWalletData;

    #[test]
    fn append_prepends_newest() {
        let _iso = IsolatedWalletData::new();
        let mut h = TxHistory::default();
        h.append(PaymentRail::L1OnChain, "abc", "1From", "1To", 1.0, "test")
            .unwrap();
        assert_eq!(h.list()[0].tx_hash, "abc");
        assert_eq!(h.list()[0].status, TxStatus::Confirmed);
    }

    #[test]
    fn pending_resolves_to_confirmed() {
        let _iso = IsolatedWalletData::new();
        let mut h = TxHistory::default();
        let key = h
            .begin_pending(PaymentRail::L1OnChain, "1From", "1To", 0.09)
            .unwrap();
        assert_eq!(h.list()[0].status, TxStatus::Pending);
        h.resolve_pending(
            &key,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "Sent 0.09 HAC",
            TxStatus::Confirmed,
        )
        .unwrap();
        assert_eq!(h.list()[0].status, TxStatus::Confirmed);
        assert_eq!(h.list()[0].tx_hash.len(), 64);
    }

    #[test]
    fn pending_marks_failed() {
        let _iso = IsolatedWalletData::new();
        let mut h = TxHistory::default();
        let key = h
            .begin_pending(PaymentRail::L2Fast, "1From", "1To", 1.0)
            .unwrap();
        h.mark_failed(&key).unwrap();
        assert_eq!(h.list()[0].status, TxStatus::Failed);
    }

    #[test]
    fn pending_fast_pay_records_excludes_local_placeholders() {
        let _iso = IsolatedWalletData::new();
        let mut h = TxHistory::default();
        let local_key = h
            .begin_pending(PaymentRail::L2Fast, "1From", "1To", 1.0)
            .unwrap();
        h.append_with_status(
            PaymentRail::L2Fast,
            "hub-payment-id",
            "1From",
            "1To",
            1.0,
            "Waiting for recipient",
            TxStatus::Pending,
        )
        .unwrap();

        let records = h.pending_fast_pay_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tx_hash, "hub-payment-id");
        assert_ne!(records[0].tx_hash, local_key);
    }
}
