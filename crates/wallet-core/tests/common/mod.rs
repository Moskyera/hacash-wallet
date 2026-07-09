//! Shared helpers for wallet security audit integration tests.

use std::sync::Mutex;

use protocol::setup::{install_test_scope, new_standard_protocol_setup};
use sys::calculate_hash;

/// Serializes `HACASH_WALLET_DATA` overrides — env vars are process-global and race under parallel tests.
static WALLET_DATA_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Install scoped Hacash protocol registry (required for transaction signing in tests).
pub fn with_protocol_setup<F: FnOnce()>(f: F) {
    let setup = new_standard_protocol_setup(|_, stuff| calculate_hash(stuff));
    let _guard = install_test_scope(setup);
    f();
}

/// Isolate wallet data under a fresh temp directory for the duration of `f`.
pub fn with_isolated_wallet_dir<F: FnOnce()>(f: F) {
    let _guard = WALLET_DATA_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().expect("tempdir");
    let wallet_root = dir.path().join("wallet-data");
    std::fs::create_dir_all(&wallet_root).expect("wallet root");
    // SAFETY: test-only path override via HACASH_WALLET_DATA
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", &wallet_root);
    }
    f();
    unsafe {
        std::env::remove_var("HACASH_WALLET_DATA");
    }
    drop(dir);
}

/// Run a named audit gate — prints progress for CI logs.
pub fn audit_gate(name: &str, f: impl FnOnce()) {
    eprintln!("[AUDIT] {name}");
    f();
}

/// Run a named stress gate — prints progress for CI logs.
pub fn stress_gate(name: &str, f: impl FnOnce()) {
    eprintln!("[STRESS] {name}");
    f();
}

/// Run a named tier-0 (elite adversarial) gate — prints progress for CI logs.
pub fn tier0_gate(name: &str, f: impl FnOnce()) {
    eprintln!("[TIER0] {name}");
    f();
}