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

/// Both dApp signing commands must settle three things before they ask the user for
/// anything: that the origin actually connected, and that policy will not refuse the
/// operation anyway. Consent requested for an operation that cannot proceed teaches the
/// user that approval dialogs are noise, and an unconnected origin must learn nothing
/// about wallet state.
///
/// The order is the contract, so this asserts positions, not just presence.
#[test]
fn dapp_signing_checks_connection_and_policy_before_requesting_consent() {
    let root = repo_root();
    let dapp = read(&root, "crates/wallet-tauri-common/src/dapp_commands.rs");

    for command in [
        "pub async fn wallet_dapp_transfer(",
        "pub async fn wallet_dapp_sign_tx(",
    ] {
        let body = command_body(&dapp, command);

        let connection = body
            .find("dapp_session_is_authorized(&origin)")
            .unwrap_or_else(|| panic!("{command} must check the dApp session first"));
        let policy = body
            .find("check_dapp_signing_policy()")
            .unwrap_or_else(|| panic!("{command} must check signing policy before consent"));
        let approval = body
            .find("require_approval(")
            .unwrap_or_else(|| panic!("{command} must still request approval"));

        assert!(
            connection < policy,
            "{command} must not reveal policy state to an origin that never connected"
        );
        assert!(
            policy < approval,
            "{command} must refuse before raising the approval sheet, not after"
        );
        assert!(
            body.contains(r#"{ "err": "Wallet not connected", "ret": 1 }"#),
            "{command} must keep the existing unconnected response shape"
        );
    }

    // The wallet mutex must never be held across the approval await: require_approval
    // waits up to 120 seconds, and the sync commands use blocking_lock, so holding it
    // would freeze the interface thread rather than fail cleanly.
    let transfer = command_body(&dapp, "pub async fn wallet_dapp_transfer(");
    let guard_block = transfer
        .split_once("let svc = state.inner.lock().await;")
        .expect("scoped pre-check guard")
        .1;
    let block_end = guard_block.find('}').expect("pre-check block must close");
    let approval_offset = guard_block
        .find("require_approval(")
        .expect("approval call after the pre-check");
    assert!(
        block_end < approval_offset,
        "the pre-check guard must be dropped before require_approval is awaited"
    );
}
