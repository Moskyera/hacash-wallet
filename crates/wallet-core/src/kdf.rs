//! Argon2id parameters per security profile.
//! Balanced: faster unlock (Electrum-class responsiveness).
//! Paranoid: stronger than typical Bitcoin Core wallet encryption.

use crate::error::{WalletError, WalletResult};

// Imported metadata is bounded before Argon2 allocates memory or worker lanes.
pub const MIN_MEMORY_COST_KIB: u32 = 19 * 1024;
pub const MAX_MEMORY_COST_KIB: u32 = 256 * 1024;
pub const MIN_TIME_COST: u32 = 1;
pub const MAX_TIME_COST: u32 = 10;
pub const MIN_PARALLELISM: u32 = 1;
pub const MAX_PARALLELISM: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Faster unlock than the legacy profile while retaining bounded Argon2id work factors.
    pub fn balanced() -> Self {
        Self {
            m_cost: 32_768,
            t_cost: 2,
            p_cost: 2,
        }
    }

    /// Higher-cost software-vault profile. It does not make an exportable software key equivalent to hardware custody.
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
    pub fn try_from_profile(name: &str) -> WalletResult<Self> {
        match name {
            "balanced" => Ok(Self::balanced()),
            "paranoid" => Ok(Self::paranoid()),
            _ => Err(WalletError::Vault("unknown security profile".into())),
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
        let parts: Vec<_> = label.split(',').collect();
        if parts.len() != 3 {
            return Err(WalletError::Vault("invalid kdf parameter count".into()));
        }
        for part in parts {
            let part = part.trim();
            if let Some(v) = part.strip_prefix("m=") {
                if m_cost.is_some() {
                    return Err(WalletError::Vault("duplicate kdf m".into()));
                }
                m_cost = Some(
                    v.parse()
                        .map_err(|_| WalletError::Vault("invalid kdf m".into()))?,
                );
            } else if let Some(v) = part.strip_prefix("t=") {
                if t_cost.is_some() {
                    return Err(WalletError::Vault("duplicate kdf t".into()));
                }
                t_cost = Some(
                    v.parse()
                        .map_err(|_| WalletError::Vault("invalid kdf t".into()))?,
                );
            } else if let Some(v) = part.strip_prefix("p=") {
                if p_cost.is_some() {
                    return Err(WalletError::Vault("duplicate kdf p".into()));
                }
                p_cost = Some(
                    v.parse()
                        .map_err(|_| WalletError::Vault("invalid kdf p".into()))?,
                );
            } else {
                return Err(WalletError::Vault("unknown kdf parameter".into()));
            }
        }
        let parsed = Self {
            m_cost: m_cost.ok_or_else(|| WalletError::Vault("kdf missing m".into()))?,
            t_cost: t_cost.ok_or_else(|| WalletError::Vault("kdf missing t".into()))?,
            p_cost: p_cost.ok_or_else(|| WalletError::Vault("kdf missing p".into()))?,
        };
        parsed.validate_bounds()?;
        Ok(parsed)
    }

    pub fn from_metadata_kdf(kdf: &str) -> WalletResult<Self> {
        let rest = kdf
            .strip_prefix("argon2id-")
            .ok_or_else(|| WalletError::Vault(format!("unsupported kdf: {kdf}")))?;
        Self::parse_label(rest)
    }

    pub fn validate_bounds(&self) -> WalletResult<()> {
        if !(MIN_MEMORY_COST_KIB..=MAX_MEMORY_COST_KIB).contains(&self.m_cost) {
            return Err(WalletError::Vault(
                "kdf memory cost outside safe limits".into(),
            ));
        }
        if !(MIN_TIME_COST..=MAX_TIME_COST).contains(&self.t_cost) {
            return Err(WalletError::Vault(
                "kdf time cost outside safe limits".into(),
            ));
        }
        if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.p_cost) {
            return Err(WalletError::Vault(
                "kdf parallelism outside safe limits".into(),
            ));
        }
        if self.m_cost < 8 * self.p_cost {
            return Err(WalletError::Vault(
                "kdf memory cost is too small for its parallelism".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitted_profiles_are_inside_import_bounds() {
        KdfParams::balanced().validate_bounds().unwrap();
        KdfParams::paranoid().validate_bounds().unwrap();
        KdfParams::legacy_v1().validate_bounds().unwrap();
    }

    #[test]
    fn imported_kdf_rejects_resource_exhaustion_and_ambiguous_labels() {
        assert!(KdfParams::parse_label("m=4294967295,t=2,p=1").is_err());
        assert!(KdfParams::parse_label("m=32768,t=4294967295,p=1").is_err());
        assert!(KdfParams::parse_label("m=32768,t=2,p=99").is_err());
        assert!(KdfParams::parse_label("m=32768,m=32768,p=1").is_err());
        assert!(KdfParams::parse_label("m=32768,t=2,p=1,x=1").is_err());
    }
}
