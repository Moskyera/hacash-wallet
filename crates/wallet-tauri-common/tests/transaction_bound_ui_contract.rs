use std::{fs, path::PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    fs::read_to_string(workspace_root().join(relative)).expect(relative)
}

#[test]
fn renderer_has_no_empty_operation_id_authorization_fallback() {
    for api in ["apps/desktop/src/api.ts", "apps/mobile/src/api.ts"] {
        let source = read(api);
        assert!(!source.contains("operationId = \"\""), "{api}");
    }

    for panel in [
        "apps/desktop/src/components/DappApprovalPanel.tsx",
        "apps/mobile/src/components/DappApprovalPanel.tsx",
    ] {
        let source = read(panel);
        assert!(
            source.contains("exact transaction bytes can be prepared and bound"),
            "{panel} must fail closed until dApp bytes are prepared"
        );
        assert!(!source.contains("confirmBiometricNative()"), "{panel}");
        assert!(!source.contains("confirmBiometric()"), "{panel}");
    }
}

#[test]
fn protected_quantum_signing_is_explicitly_fail_closed() {
    for screen in [
        "apps/desktop/src/components/SendQuantumTx.tsx",
        "apps/mobile/src/components/QuantumScreen.tsx",
    ] {
        assert!(
            read(screen).contains("authorization can bind to the exact Type 4 body"),
            "{screen}"
        );
    }
}
