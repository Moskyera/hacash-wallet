use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf()
}

fn function_signature<'a>(source: &'a str, function: &str) -> &'a str {
    let start = source.find(function).expect("command exists");
    let end = source[start..]
        .find(") ->")
        .map(|offset| start + offset)
        .expect("command signature ends");
    &source[start..end]
}

#[test]
fn prepared_execution_ipc_accepts_only_opaque_operation_id() {
    let source = fs::read_to_string(
        workspace_root().join("crates/wallet-tauri-common/src/prepared_commands.rs"),
    )
    .unwrap();
    for command in [
        "pub async fn wallet_execute_prepared_hac(",
        "pub async fn wallet_execute_prepared_hacd(",
        "pub async fn wallet_execute_prepared_btc(",
        "pub async fn wallet_execute_prepared_channel_open(",
        "pub async fn wallet_execute_prepared_channel_close(",
        "pub fn wallet_execute_prepared_airgap_sign(",
    ] {
        let signature = function_signature(&source, command);
        assert!(signature.contains("operation_id: String"), "{command}");
        for forbidden in ["body", "unsigned", "amount", "satoshi", "to:", "fee"] {
            assert!(
                !signature.contains(forbidden),
                "{command} accepts mutable renderer field {forbidden}"
            );
        }
    }
}

#[test]
fn platform_authentication_ipc_requires_prepared_operation_id() {
    let root = workspace_root();
    let security =
        fs::read_to_string(root.join("crates/wallet-tauri-common/src/security_commands.rs"))
            .unwrap();
    for command in [
        "pub fn wallet_webauthn_auth_begin(",
        "pub fn wallet_webauthn_auth_finish(",
    ] {
        assert!(
            function_signature(&security, command).contains("operation_id: String"),
            "{command} must be transaction-bound"
        );
    }
    for app in ["desktop", "mobile"] {
        let source =
            fs::read_to_string(root.join(format!("apps/{app}/src-tauri/src/lib.rs"))).unwrap();
        assert!(
            function_signature(&source, "fn wallet_confirm_biometric_native(")
                .contains("operation_id: String"),
            "{app} native authentication must be transaction-bound"
        );
    }
}
