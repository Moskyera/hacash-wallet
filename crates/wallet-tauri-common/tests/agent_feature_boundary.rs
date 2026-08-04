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
        "dep:agent-wallet-runtime",
        "dep:hpay-agent-connector",
        "dep:hpay-companion-protocol",
        "dep:hpay-companion-lan-runtime",
    ]);
    assert_eq!(actual_dependencies, expected_dependencies);
    let target_guard = "not(any(target_os = \"android\", target_os = \"ios\"))";
    assert_eq!(library.matches(target_guard).count(), 5);
    assert!(library.contains("pub mod agent_commands;"));
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
