//! Local privacy controls: display masking, optional history storage, clipboard hygiene.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacySettings {
    /// Mask balances in UI (amounts still fetched for signing checks).
    #[serde(default)]
    pub hide_balances: bool,
    /// Mask addresses and tx hashes in lists and previews.
    #[serde(default)]
    pub hide_addresses: bool,
    /// Blur wallet UI when the window loses focus.
    #[serde(default = "default_screen_privacy")]
    pub screen_privacy: bool,
    /// Persist new transactions to local history.
    #[serde(default = "default_true")]
    pub store_tx_history: bool,
    /// Auto-clear clipboard N seconds after copy (0 = disabled).
    #[serde(default = "default_clipboard_clear_secs")]
    pub clipboard_clear_secs: u64,
    /// While connected to HACD Launchpad (hacd.it), reset the auto-lock idle timer.
    #[serde(default = "default_true")]
    pub pause_auto_lock_dapp: bool,
}

fn default_screen_privacy() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_clipboard_clear_secs() -> u64 {
    30
}

impl Default for PrivacySettings {
    fn default() -> Self {
        Self {
            hide_balances: false,
            hide_addresses: false,
            screen_privacy: default_screen_privacy(),
            store_tx_history: default_true(),
            clipboard_clear_secs: default_clipboard_clear_secs(),
            pause_auto_lock_dapp: default_true(),
        }
    }
}

pub fn mask_address(address: &str) -> String {
    let trimmed = address.trim();
    if trimmed.len() <= 10 {
        return "••••••••".into();
    }
    format!(
        "{}…{}",
        &trimmed[..6.min(trimmed.len())],
        &trimmed[trimmed.len().saturating_sub(4)..]
    )
}

pub fn mask_hash(hash: &str) -> String {
    let trimmed = hash.trim();
    if trimmed.len() <= 12 {
        return "••••••••".into();
    }
    format!(
        "{}…{}",
        &trimmed[..8.min(trimmed.len())],
        &trimmed[trimmed.len().saturating_sub(6)..]
    )
}

pub fn mask_amount(amount_mei: f64) -> String {
    if amount_mei.is_finite() {
        "•••• HAC".into()
    } else {
        "••••".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_address_shortens_middle() {
        let m = mask_address("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS");
        assert!(m.contains('…'));
        assert!(!m.contains("Fi3rd"));
    }

    #[test]
    fn privacy_defaults_screen_on() {
        let p = PrivacySettings::default();
        assert!(p.screen_privacy);
        assert!(p.store_tx_history);
        assert_eq!(p.clipboard_clear_secs, 30);
        assert!(p.pause_auto_lock_dapp);
    }
}