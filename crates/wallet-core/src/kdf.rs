//! Argon2id parameters per security profile.
//! Balanced: faster unlock (Electrum-class responsiveness).
//! Paranoid: stronger than typical Bitcoin Core wallet encryption.

use crate::error::{WalletError, WalletResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// ~2× faster unlock vs legacy m=65536,t=3,p=4 — still OWASP-grade for desktop.
    pub fn balanced() -> Self {
        Self {
            m_cost: 32_768,
            t_cost: 2,
            p_cost: 2,
        }
    }

    /// Stronger than legacy; intended to exceed Bitcoin Core / hardware-wallet KDF bar.
    pub fn paranoid() -> Self {
        Self {
            m_cost: 131_072,
            t_cost: 4,
            p_cost: 4,
        }
    }

    /// Legacy vaults created before profile-based KDF.
    pub fn legacy_v1() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 4,
        }
    }

    pub fn from_profile(name: &str) -> Self {
        if name == "paranoid" {
            Self::paranoid()
        } else {
            Self::balanced()
        }
    }

    pub fn label(&self) -> String {
        format!(
            "argon2id-m={},t={},p={}",
            self.m_cost, self.t_cost, self.p_cost
        )
    }

    pub fn parse_label(label: &str) -> WalletResult<Self> {
        let mut m_cost = None;
        let mut t_cost = None;
        let mut p_cost = None;
        for part in label.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("m=") {
                m_cost = Some(v.parse().map_err(|_| WalletError::Vault("invalid kdf m".into()))?);
            } else if let Some(v) = part.strip_prefix("t=") {
                t_cost = Some(v.parse().map_err(|_| WalletError::Vault("invalid kdf t".into()))?);
            } else if let Some(v) = part.strip_prefix("p=") {
                p_cost = Some(v.parse().map_err(|_| WalletError::Vault("invalid kdf p".into()))?);
            }
        }
        Ok(Self {
            m_cost: m_cost.ok_or_else(|| WalletError::Vault("kdf missing m".into()))?,
            t_cost: t_cost.ok_or_else(|| WalletError::Vault("kdf missing t".into()))?,
            p_cost: p_cost.ok_or_else(|| WalletError::Vault("kdf missing p".into()))?,
        })
    }

    pub fn from_metadata_kdf(kdf: &str) -> WalletResult<Self> {
        let rest = kdf
            .strip_prefix("argon2id-")
            .ok_or_else(|| WalletError::Vault(format!("unsupported kdf: {kdf}")))?;
        Self::parse_label(rest)
    }
}