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

/// The core builds a trusted display for every prepared operation, but a WebAuthn
/// prompt cannot render operation detail and a bare biometric prompt states no
/// purpose. If the renderer does not show that display itself, nobody ever sees
/// what they are approving, and the two-phase design loses the half that protects
/// the human rather than the bytes.
#[test]
fn every_ceremony_shows_the_trusted_display_first() {
    for authorization in [
        "apps/desktop/src/preparedAuthorization.ts",
        "apps/mobile/src/preparedAuthorization.ts",
    ] {
        let source = read(authorization);
        let confirm = source
            .find("requestPreparedConfirmation")
            .unwrap_or_else(|| panic!("{authorization} must confirm before any ceremony"));
        for ceremony in ["confirmBiometric", "webauthnAuthBegin", "runWebAuthnAuth"] {
            if let Some(at) = source.find(ceremony) {
                assert!(
                    confirm < at,
                    "{authorization}: {ceremony} runs before the trusted display is shown"
                );
            }
        }
        assert!(
            source.contains("Operation cancelled"),
            "{authorization} must abort when the user declines"
        );
    }

    // The dialog has to be mounted, or the confirmation can never resolve.
    for (root, component) in [
        (
            "apps/desktop/src/App.tsx",
            "apps/desktop/src/components/PreparedOperationConfirm.tsx",
        ),
        (
            "apps/mobile/src/MobileApp.tsx",
            "apps/mobile/src/components/PreparedOperationConfirm.tsx",
        ),
    ] {
        assert!(
            read(root).contains("<PreparedOperationConfirm />"),
            "{root} must mount the prepared-operation dialog"
        );
        let source = read(component);
        assert!(source.contains("view.display.fields.map"), "{component}");
        assert!(source.contains("view.display.title"), "{component}");
    }

    // A missing host must fail, never hang: an approval nobody settles looks
    // exactly like a frozen wallet.
    for bridge in [
        "apps/desktop/src/preparedConfirm.ts",
        "apps/mobile/src/preparedConfirm.ts",
    ] {
        assert!(
            read(bridge).contains("Promise.reject"),
            "{bridge} must fail closed"
        );
    }
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
fn fast_pay_channel_open_is_prepared_only_on_both_apps() {
    for handler in [
        "apps/desktop/src/hooks/useDesktopWallet.ts",
        "apps/mobile/src/hooks/useWalletSession.ts",
        "apps/mobile/src/screens/FastPayChannelScreen.tsx",
    ] {
        let source = read(handler);
        assert!(
            !source.contains("api.enableFastPay("),
            "{handler} must never call the legacy unprepared channel-open command"
        );
        assert!(
            source.contains("prepareChannelOpen"),
            "{handler} must prepare and display the exact channel transaction"
        );
        assert!(
            source.contains("executePreparedChannelOpen"),
            "{handler} must execute only the reviewed prepared operation"
        );
    }

    let wallet = read("crates/wallet-core/src/wallet.rs");
    let enable = wallet
        .split_once("    pub async fn enable_fast_pay(")
        .expect("Fast Pay compatibility command")
        .1
        .split_once("    pub async fn fast_pay_status(")
        .expect("Fast Pay method boundary")
        .0;
    assert!(
        !enable.contains("self.open_channel("),
        "the compatibility command must configure only and never sign an L1 channel open"
    );
}
#[test]
fn fast_pay_open_close_previews_are_exact_and_recoverable_on_both_apps() {
    let service = read("crates/wallet-core/src/wallet/authorization_service.rs");
    let open = service
        .split_once("    pub async fn prepare_channel_open(")
        .expect("channel-open prepare method")
        .1
        .split_once("    pub async fn execute_prepared_channel_open(")
        .expect("channel-open execution boundary")
        .0;
    for field in [
        "Your deposit",
        "Hub deposit",
        "Network fee",
        "Wallet fee",
        "Channel",
    ] {
        assert!(open.contains(field), "channel-open preview missing {field}");
    }
    assert!(open.contains("exact_transaction_display"));

    let close = service
        .split_once("    pub async fn prepare_channel_close(")
        .expect("channel-close prepare method")
        .1
        .split_once("    pub async fn execute_prepared_channel_close(")
        .expect("channel-close execution boundary")
        .0;
    for field in [
        "Original L1 distribution",
        "Network fee",
        "Wallet fee",
        "Channel",
    ] {
        assert!(
            close.contains(field),
            "channel-close preview missing {field}"
        );
    }

    for (api, screen) in [
        (
            "apps/desktop/src/api.ts",
            "apps/desktop/src/screens/FastPayScreen.tsx",
        ),
        (
            "apps/mobile/src/api.ts",
            "apps/mobile/src/screens/FastPayChannelScreen.tsx",
        ),
    ] {
        assert!(read(api).contains("recoverChannelOpen"), "{api}");
        let screen = read(screen);
        assert!(screen.contains("Finish pending setup"), "{screen}");
        assert!(screen.contains("recoverChannelOpen"), "{screen}");
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
