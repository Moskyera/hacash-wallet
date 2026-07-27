use serde::{Deserialize, Serialize};

use crate::error::{WalletError, WalletResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    pub name: String,
    pub auto_lock_secs: u64,
    pub require_second_factor_above_mei: u64,
    pub yubikey_required: bool,
    pub biometric_unlock: bool,
}

impl Default for SecurityProfile {
    fn default() -> Self {
        Self {
            name: "balanced".into(),
            auto_lock_secs: 180,
            require_second_factor_above_mei: 100,
            yubikey_required: false,
            biometric_unlock: true,
        }
    }
}

impl SecurityProfile {
    pub fn paranoid() -> Self {
        Self {
            name: "paranoid".into(),
            auto_lock_secs: 60,
            require_second_factor_above_mei: 1,
            yubikey_required: true,
            biometric_unlock: false,
        }
    }

    pub fn from_name(name: &str) -> Self {
        if name == "paranoid" {
            Self::paranoid()
        } else {
            Self::default()
        }
    }
}

/// Combine the profile's threshold with the user's chosen one.
///
/// `ceiling` comes from the security profile, which is bound to the vault through the
/// profile name. `chosen` comes from the settings file, which is not bound to anything.
/// Taking the minimum is the whole safety argument: a settings file that someone edited
/// or replaced can only make the policy stricter than the profile allows, never weaker,
/// so it does not need to be authenticated.
///
/// Two callers need this, one for enforcement and one for what the interface displays,
/// and they must never disagree. That is why the formula lives here once rather than
/// being written out at each site.
pub fn effective_second_factor_threshold(ceiling: u64, chosen: Option<u64>) -> u64 {
    match chosen {
        // A zero would read as "no threshold at all", which is the opposite of what
        // choosing a small number means. Normalisation rejects it; this clamps anyway
        // rather than trusting a file.
        Some(value) => value.clamp(1, ceiling.max(1)),
        None => ceiling,
    }
}

#[derive(Debug, Clone)]
pub struct UnlockContext {
    pub biometric_ok: bool,
    pub yubikey_ok: bool,
}

pub fn check_send_policy(
    profile: &SecurityProfile,
    amount_mei: u64,
    ctx: &UnlockContext,
) -> WalletResult<()> {
    if amount_mei >= profile.require_second_factor_above_mei {
        if profile.yubikey_required && !ctx.yubikey_ok {
            return Err(WalletError::Policy(
                "YubiKey confirmation required for this amount".into(),
            ));
        }
        if profile.biometric_unlock && !ctx.biometric_ok && !ctx.yubikey_ok {
            return Err(WalletError::Policy(
                "Biometric or YubiKey confirmation required".into(),
            ));
        }
    }
    Ok(())
}
