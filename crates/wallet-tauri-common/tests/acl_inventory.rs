use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const COMMAND_PREFIXES: [&str; 3] = ["wallet_", "quantum_", "messenger_"];
const LAUNCHPAD_COMMANDS: [&str; 7] = [
    "wallet_dapp_connect",
    "wallet_dapp_disconnect",
    "wallet_dapp_wallet",
    "wallet_dapp_heartbeat",
    "wallet_dapp_transfer",
    "wallet_dapp_sign_tx",
    "wallet_dapp_chain",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn command_from_line(line: &str) -> Option<String> {
    let token = line.trim().strip_suffix(',')?.trim();
    let name = token.rsplit("::").next()?;
    COMMAND_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        .then(|| name.to_string())
}

fn command_block(source: &str, start: &str, end: &str) -> BTreeSet<String> {
    let source = source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing command block start: {start}"))
        .1;
    let source = source
        .split_once(end)
        .unwrap_or_else(|| panic!("missing command block end: {end}"))
        .0;
    source.lines().filter_map(command_from_line).collect()
}

fn registered_commands(root: &Path, app: &str) -> BTreeSet<String> {
    let common = command_block(
        &read(root, "crates/wallet-tauri-common/src/handlers.rs"),
        "tauri::generate_handler![",
        "$($extra),*",
    );
    let extras = command_block(
        &read(root, &format!("apps/{app}/src-tauri/src/lib.rs")),
        "wallet_invoke_handler![",
        "])",
    );
    common.union(&extras).cloned().collect()
}

fn permission_commands(source: &str, identifier: &str) -> BTreeSet<String> {
    source
        .split("[[permission]]")
        .find(|section| {
            section
                .lines()
                .any(|line| line.trim() == format!("identifier = \"{identifier}\""))
        })
        .unwrap_or_else(|| panic!("missing permission {identifier}"))
        .lines()
        .filter_map(|line| {
            let value = line.trim().strip_prefix('"')?.strip_suffix("\",")?;
            COMMAND_PREFIXES
                .iter()
                .any(|prefix| value.starts_with(prefix))
                .then(|| value.to_string())
        })
        .collect()
}

fn assert_capability_scope(root: &Path, app: &str, launchpad_permission: &str) {
    let default: serde_json::Value = serde_json::from_str(&read(
        root,
        &format!("apps/{app}/src-tauri/capabilities/default.json"),
    ))
    .expect("valid default capability JSON");
    assert_eq!(default["webviews"], serde_json::json!(["main"]));
    assert!(default.get("windows").is_none());
    assert!(
        default["permissions"]
            .as_array()
            .expect("default permissions")
            .iter()
            .any(|value| value == "allow-main-wallet")
    );

    let launchpad: serde_json::Value = serde_json::from_str(&read(
        root,
        &format!("apps/{app}/src-tauri/capabilities/launchpad.json"),
    ))
    .expect("valid launchpad capability JSON");
    assert_eq!(launchpad["webviews"], serde_json::json!(["launchpad"]));
    assert_eq!(
        launchpad["permissions"],
        serde_json::json!([launchpad_permission])
    );
    assert_eq!(
        launchpad["remote"]["urls"],
        serde_json::json!(["https://hacd.it/*"])
    );
}

fn assert_app_acl(root: &Path, app: &str, launchpad_permission: &str) {
    let permission_file = read(
        root,
        &format!("apps/{app}/src-tauri/permissions/wallet.toml"),
    );
    let registered = registered_commands(root, app);
    let main = permission_commands(&permission_file, "allow-main-wallet");
    assert_eq!(
        main, registered,
        "{app} main-wallet ACL must exactly match its registered invoke commands"
    );

    let launchpad = permission_commands(&permission_file, launchpad_permission);
    assert_eq!(
        launchpad,
        LAUNCHPAD_COMMANDS.into_iter().map(str::to_string).collect(),
        "{app} Launchpad ACL must stay least-privilege"
    );
    assert_capability_scope(root, app, launchpad_permission);
}

#[test]
fn desktop_and_mobile_acl_match_handler_inventory_and_isolate_launchpad() {
    let root = repo_root();
    assert_app_acl(&root, "desktop", "allow-launchpad-dapp");
    assert_app_acl(&root, "mobile", "allow-dapp-bridge");
}
