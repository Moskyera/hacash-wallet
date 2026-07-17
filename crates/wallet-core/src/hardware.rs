//! Hardware / platform signing policies (watch-only, WebAuthn-gated software key).

use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

/// How transaction signing is authorized on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSigningMode {
    /// Standard software key in encrypted vault.
    #[default]
    Software,
    /// Every sign requires a fresh WebAuthn ceremony (YubiKey / Windows Hello).
    WebAuthnGate,
    /// Address-only wallet. cannot sign locally (Sparrow-style watch-only).
    WatchOnly,
}

impl HardwareSigningMode {
    pub fn from_name(name: &str) -> Self {
        match name {
            "webauthn_gate" => Self::WebAuthnGate,
            "watch_only" => Self::WatchOnly,
            _ => Self::Software,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::WebAuthnGate => "webauthn_gate",
            Self::WatchOnly => "watch_only",
        }
    }
}

pub fn check_signing_allowed(
    mode: HardwareSigningMode,
    watch_only: bool,
    webauthn_verified: bool,
) -> WalletResult<()> {
    if watch_only || mode == HardwareSigningMode::WatchOnly {
        return Err(WalletError::Policy(
            "watch-only wallet cannot sign. use hardware device or import signing key".into(),
        ));
    }
    if mode == HardwareSigningMode::WebAuthnGate && !webauthn_verified {
        return Err(WalletError::Policy(
            "hardware gate: complete WebAuthn (YubiKey/Windows Hello) before signing".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_only_blocks_sign() {
        assert!(check_signing_allowed(HardwareSigningMode::WatchOnly, true, true).is_err());
    }

    #[test]
    fn webauthn_gate_requires_verified() {
        assert!(check_signing_allowed(HardwareSigningMode::WebAuthnGate, false, false).is_err());
        assert!(check_signing_allowed(HardwareSigningMode::WebAuthnGate, false, true).is_ok());
    }
}
