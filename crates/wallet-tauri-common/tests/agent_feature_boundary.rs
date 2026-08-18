use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn agent_core_is_optional_and_the_admin_surface_is_feature_gated() {
    let manifest = read("crates/wallet-tauri-common/Cargo.toml");
    let library = read("crates/wallet-tauri-common/src/lib.rs");
    let state = read("crates/wallet-tauri-common/src/state.rs");

    assert!(manifest.contains(
        "[target.'cfg(not(any(target_os = \"android\", target_os = \"ios\")))'.dependencies]"
    ));
    assert!(
        manifest
            .contains("agent-wallet-core = { path = \"../agent-wallet-core\", optional = true }")
    );
    assert!(manifest.contains(
        "agent-wallet-runtime = { path = \"../agent-wallet-runtime\", optional = true, features = [\"listener\"] }"
    ));
    assert!(manifest.contains(
        "hpay-agent-connector = { path = \"../agent-connector\", optional = true, default-features = false }"
    ));
    let (_, feature_tail) = manifest
        .split_once("agent-wallet-admin = [")
        .expect("agent-wallet-admin feature");
    let (feature_body, _) = feature_tail
        .split_once(']')
        .expect("feature closing bracket");
    let actual_dependencies: BTreeSet<_> = feature_body
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix('"')?.strip_suffix("\","))
        .collect();
    let expected_dependencies = BTreeSet::from([
        "dep:agent-wallet-core",
        // Read only, and only on the desktop admin surface: the fullnode query
        // that reports a registry channel's remaining storage lease, and the
        // measured readiness of the user side of the unilateral exit. No Hub
        // is started and no Hub endpoint is called from this crate. It is
        // listed here so that adding a *second* reason to depend on the Hub
        // crate has to be a deliberate edit to this set.
        "dep:l2-fast-pay-hub",
        "dep:agent-wallet-runtime",
        "dep:hpay-agent-connector",
        "dep:hpay-companion-protocol",
        "dep:hpay-companion-lan-runtime",
    ]);
    assert_eq!(actual_dependencies, expected_dependencies);
    let target_guard = "not(any(target_os = \"android\", target_os = \"ios\"))";
    // Seven, not six: `agent_registry_exit` is the desktop-only view of a
    // fullnode that the unilateral exit driver reads a channel through, and
    // `agent_registry_open` is its twin for the other end of a channel's life.
    // Both are guarded twice over - by this target guard and by the pilot
    // feature - because a phone holds an approval identity rather than a
    // Hacash key, so it can neither open a channel nor exit one.
    //
    // `agent_registry_open` shipped without any cfg at all and broke the
    // Android build with four E0433s: this crate takes l2-fast-pay-hub as an
    // optional dependency, so the module named a crate that was never linked.
    // The count is asserted here precisely so adding a guard has to be a
    // deliberate edit rather than a number that drifts.
    assert_eq!(library.matches(target_guard).count(), 7);
    assert!(library.contains("pub mod agent_commands;"));
    assert!(library.contains("pub mod agent_registry_exit;"));
    assert!(library.contains("pub mod agent_registry_open;"));
    assert!(library.contains("pub mod agent_runtime;"));
    assert!(library.contains("pub mod companion_backend;"));
    assert!(library.contains("pub mod companion_runtime;"));
    assert!(library.contains("pub use state::AgentAppState;"));
    assert_eq!(state.matches(target_guard).count(), 3);
    assert!(state.contains("pub struct AgentAppState"));
    assert!(state.contains("impl AgentAppState"));
}

#[test]
fn desktop_enables_agent_admin_while_mobile_does_not() {
    let desktop_manifest = read("apps/desktop/src-tauri/Cargo.toml");
    let mobile_manifest = read("apps/mobile/src-tauri/Cargo.toml");
    let desktop_entry = read("apps/desktop/src-tauri/src/lib.rs");
    let mobile_entry = read("apps/mobile/src-tauri/src/lib.rs");

    assert!(desktop_manifest.contains("features = [\"desktop\", \"agent-wallet-admin\"]"));
    assert!(!mobile_manifest.contains("agent-wallet-admin"));
    assert!(!mobile_manifest.contains("agent-wallet-runtime"));
    assert!(desktop_entry.contains("use wallet_tauri_common::{AgentAppState, AppState};"));
    assert!(desktop_entry.contains("wallet_tauri_common::agent_commands::agent_wallet_create"));
    assert!(!mobile_entry.contains("AgentAppState"));
    assert!(!mobile_entry.contains("wallet_tauri_common::agent_commands::"));
}
