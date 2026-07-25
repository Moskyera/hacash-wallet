use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn command_body<'a>(source: &'a str, command: &str) -> &'a str {
    source
        .split_once(command)
        .unwrap_or_else(|| panic!("missing command {command}"))
        .1
        .split_once("#[tauri::command]")
        .map(|(body, _)| body)
        .unwrap_or_else(|| panic!("missing command boundary after {command}"))
}

#[test]
fn reset_ipc_requires_passphrase_and_exact_address_before_deletion() {
    let root = repo_root();
    let commands = read(&root, "crates/wallet-tauri-common/src/commands.rs");
    let reset = command_body(&commands, "pub async fn wallet_reset(");

    for contract in [
        "current_passphrase: Option<String>",
        "confirmation_address: String",
        "app: AppHandle",
        "authorize_wallet_reset(",
        "current_passphrase.as_ref().map(|value| value.as_str())",
        "clear_native_biometric_secret(&app).await?",
        "if final_kind != initial_kind",
        "svc.reset_wallet()",
    ] {
        assert!(
            reset.contains(contract),
            "reset contract is missing {contract}"
        );
    }

    assert_eq!(reset.matches("authorize_wallet_reset(").count(), 2);
    let authorize = reset
        .find("authorize_wallet_reset(")
        .expect("initial authorization");
    let native_clear = reset
        .find("clear_native_biometric_secret")
        .expect("native cleanup");
    let reauthorize = reset
        .rfind("authorize_wallet_reset(")
        .expect("authorization after native I/O");
    let delete = reset.find("svc.reset_wallet").expect("wallet deletion");
    assert!(authorize < native_clear && native_clear < reauthorize && reauthorize < delete);

    let policy = command_body(&commands, "fn authorize_wallet_reset(");
    for contract in [
        "if status.watch_only",
        "current passphrase is required to reset a signing wallet",
        "svc.verify_wallet_passphrase(passphrase)",
        "require_exact_wallet_address(status.address, confirmation_address)",
    ] {
        assert!(
            policy.contains(contract),
            "reset policy is missing {contract}"
        );
    }
}

#[test]
fn passphrase_change_disables_and_clears_biometric_unlock() {
    let root = repo_root();
    let commands = read(&root, "crates/wallet-tauri-common/src/commands.rs");
    let change = command_body(&commands, "pub async fn wallet_change_passphrase(");

    for contract in [
        "old_passphrase: String",
        "new_passphrase: String",
        "app: AppHandle",
        "svc.change_passphrase(&old_passphrase, &new_passphrase)",
        "clear_native_biometric_secret(&app).await",
        "biometric_unlock_disabled: true",
        "native_biometric_secret_cleared: cleanup.is_ok()",
    ] {
        assert!(
            change.contains(contract),
            "passphrase-change contract is missing {contract}"
        );
    }
}
