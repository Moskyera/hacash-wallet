//! AUDIT-GATE: Send policy & second-factor enforcement

mod common;

use common::audit_gate;
use hacash_wallet_core::security::{check_send_policy, SecurityProfile, UnlockContext};
use hacash_wallet_core::WalletError;

fn ctx(bio: bool, yubi: bool) -> UnlockContext {
    UnlockContext {
        biometric_ok: bio,
        yubikey_ok: yubi,
    }
}

#[test]
fn audit_balanced_allows_small_send_without_2fa() {
    audit_gate("balanced_small_send", || {
        let p = SecurityProfile::default();
        assert!(check_send_policy(&p, 50, &ctx(false, false)).is_ok());
    });
}

#[test]
fn audit_balanced_blocks_large_without_2fa() {
    audit_gate("balanced_large_blocked", || {
        let p = SecurityProfile::default();
        let err = check_send_policy(&p, 100, &ctx(false, false)).unwrap_err();
        assert!(matches!(err, WalletError::Policy(_)));
    });
}

#[test]
fn audit_balanced_large_ok_with_biometric() {
    audit_gate("balanced_biometric_ok", || {
        let p = SecurityProfile::default();
        assert!(check_send_policy(&p, 500, &ctx(true, false)).is_ok());
    });
}

#[test]
fn audit_balanced_large_ok_with_yubikey() {
    audit_gate("balanced_yubikey_ok", || {
        let p = SecurityProfile::default();
        assert!(check_send_policy(&p, 500, &ctx(false, true)).is_ok());
    });
}

#[test]
fn audit_paranoid_requires_yubikey_at_any_amount() {
    audit_gate("paranoid_yubikey_required", || {
        let p = SecurityProfile::paranoid();
        assert!(check_send_policy(&p, 1, &ctx(true, false)).is_err());
        assert!(check_send_policy(&p, 1, &ctx(false, true)).is_ok());
    });
}

#[test]
fn audit_paranoid_biometric_alone_insufficient() {
    audit_gate("paranoid_no_biometric_only", || {
        let p = SecurityProfile::paranoid();
        let err = check_send_policy(&p, 10, &ctx(true, false)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("YubiKey"));
    });
}

#[test]
fn audit_threshold_boundary_exact() {
    audit_gate("threshold_boundary", || {
        let p = SecurityProfile::default();
        assert!(check_send_policy(&p, 99, &ctx(false, false)).is_ok());
        assert!(check_send_policy(&p, 100, &ctx(false, false)).is_err());
    });
}