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
    /// Irreversible cold-vault mode. Only an exact, freshly authorized
    /// prepared classic air-gap transaction may reach the software key.
    AirgapOnly,
    /// Address-only wallet. cannot sign locally (Sparrow-style watch-only).
    WatchOnly,
}

impl HardwareSigningMode {
    pub fn from_name(name: &str) -> Self {
        match name {
            "webauthn_gate" => Self::WebAuthnGate,
            "airgap_only" => Self::AirgapOnly,
            "watch_only" => Self::WatchOnly,
            _ => Self::Software,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::WebAuthnGate => "webauthn_gate",
            Self::AirgapOnly => "airgap_only",
            Self::WatchOnly => "watch_only",
        }
    }
}

/// The signing call-site context is intentionally crate-private. Renderer,
/// IPC and audit callers can only reach the ordinary online context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigningContext {
    Online,
    PreparedAirgap,
}

pub fn check_signing_allowed(
    mode: HardwareSigningMode,
    watch_only: bool,
    webauthn_verified: bool,
) -> WalletResult<()> {
    check_signing_allowed_in_context(mode, watch_only, webauthn_verified, SigningContext::Online)
}

pub(crate) fn check_signing_allowed_in_context(
    mode: HardwareSigningMode,
    watch_only: bool,
    webauthn_verified: bool,
    context: SigningContext,
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
    if mode == HardwareSigningMode::AirgapOnly && context != SigningContext::PreparedAirgap {
        return Err(WalletError::Policy(
            "cold vault permits signing only through a freshly authorized prepared Type 2 air-gap operation".into(),
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

    #[test]
    fn airgap_only_accepts_only_the_internal_prepared_context() {
        assert!(check_signing_allowed(HardwareSigningMode::AirgapOnly, false, true).is_err());
        assert!(
            check_signing_allowed_in_context(
                HardwareSigningMode::AirgapOnly,
                false,
                false,
                SigningContext::PreparedAirgap,
            )
            .is_ok()
        );
    }
}
