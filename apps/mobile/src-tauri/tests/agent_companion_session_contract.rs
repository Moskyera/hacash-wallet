use std::fs;
use std::path::{Path, PathBuf};

fn mobile_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn read(relative: &str) -> String {
    fs::read_to_string(mobile_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

#[test]
fn isolated_permission_and_handler_inventory_is_exactly_typed_read_only_companion_surface() {
    let permissions = read("src-tauri/permissions/wallet.toml");
    let capability = read("src-tauri/capabilities/agent-companion.json");
    let mobile_lib = read("src-tauri/src/lib.rs");
    let agent_permission = permissions
        .split("[[permission]]")
        .find(|section| section.contains("identifier = \"allow-agent-companion\""))
        .expect("agent companion permission");
    let main_permission = permissions
        .split("[[permission]]")
        .find(|section| section.contains("identifier = \"allow-main-wallet\""))
        .expect("main wallet permission");
    let commands = [
        "agent_wallet_companion_identity_status",
        "agent_wallet_companion_create_identity",
        "agent_wallet_companion_decide_payment",
        "agent_wallet_companion_rotation_step",
        "agent_wallet_companion_witness_anchor",
        "agent_wallet_companion_pairing_start",
        "agent_wallet_companion_pairing_cancel",
        "agent_wallet_companion_pairing_confirm",
        "agent_wallet_companion_state",
        "agent_wallet_companion_connect",
        "agent_wallet_companion_sync",
        "agent_wallet_companion_ping",
        "agent_wallet_companion_disconnect",
        "agent_wallet_companion_lifecycle",
        "agent_wallet_companion_reset",
    ];
    for command in commands {
        assert!(
            agent_permission.contains(command),
            "permission missing {command}"
        );
        assert!(mobile_lib.contains(command), "handler missing {command}");
        assert!(
            !main_permission.contains(command),
            "main UI exposes {command}"
        );
    }
    assert!(capability.contains("\"local\": true"));
    assert!(capability.contains("\"webviews\": [\"agent-companion\"]"));
    assert!(capability.contains("\"allow-agent-companion\""));
}

#[test]
fn command_dtos_cover_pairing_status_sync_ping_disconnect_lifecycle_and_reset() {
    let commands = read("src-tauri/src/agent_companion/commands.rs");
    for dto in [
        "PairingStartView",
        "PairingCompletionView",
        "CompanionPairingCancelView",
        "CompanionStoredStateView",
        "CompanionSessionView",
        "CompanionStatusSnapshotView",
        "CompanionPongView",
        "CompanionDisconnectView",
        "CompanionLifecycleRequest",
        "CompanionLifecycleView",
        "CompanionResetRequest",
        "CompanionResetView",
    ] {
        assert!(commands.contains(dto), "typed native DTO missing {dto}");
    }
    for decimal_string in [
        "sequence: String",
        "issued_at_unix: String",
        "expires_at_unix: String",
        "response_sequence: Option<String>",
    ] {
        assert!(
            commands.contains(decimal_string),
            "native DTO u64 is not a decimal string: {decimal_string}"
        );
    }
    assert!(commands.contains("ForegroundHeartbeat"));
    assert!(commands.contains("WebviewClosing"));
    assert!(commands.contains("session_allowed_in_background: false"));
}

#[test]
fn native_lifecycle_and_reset_are_race_safe_and_scoped() {
    let manager = read("src-tauri/src/agent_companion/mod.rs");
    let lifecycle = read("src-tauri/src/agent_companion/lifecycle.rs");
    let commands = read("src-tauri/src/agent_companion/commands.rs");
    let storage = read("src-tauri/src/agent_companion/storage.rs");
    for contract in [
        "lifecycle: Mutex<()>",
        "lifecycle_cancel: watch::Sender<u64>",
        "run_guarded",
        "signal_lifecycle_cancel",
        "lease_deadline",
    ] {
        assert!(
            manager.contains(contract),
            "lifecycle contract missing {contract}"
        );
    }
    for contract in [
        "WindowEvent::Suspended",
        "WindowEvent::Destroyed",
        "RunEvent::Exit",
        "expire_session_lease",
        "LEASE_WATCH_INTERVAL",
    ] {
        assert!(
            lifecycle.contains(contract),
            "native close hook missing {contract}"
        );
    }
    assert!(commands.contains("RESET COMPANION"));
    assert!(commands.contains("RetainHardwareIdentity"));
    assert!(commands.contains("self.signal_lifecycle_cancel()"));
    assert!(
        storage.contains("app_data_dir.join(\"agent-companion\")")
            || manager.contains("app_data_dir.join(\"agent-companion\")")
    );
    assert!(storage.contains("self.store.replace(None)?"));
    assert!(!commands.contains("WalletService"));
    assert!(!commands.contains("personal/"));

    let cancel = commands
        .split_once("async fn cancel_pending_pairing")
        .expect("pending pairing cancel method")
        .1
        .split_once("async fn reset_companion")
        .expect("cancel method boundary")
        .0;
    for required in [
        "self.signal_lifecycle_cancel()",
        "self.lifecycle.lock().await",
        "self.shared.current().await?.is_some()",
        "self.pending.lock().await.take()",
        "pairing_cancelled: true",
    ] {
        assert!(
            cancel.contains(required),
            "pairing cancel missing {required}"
        );
    }
    for forbidden in [
        "self.active",
        "self.shared.reset",
        "lease_deadline",
        "identity",
        "registry",
        "replay",
    ] {
        assert!(
            !cancel.contains(forbidden),
            "pairing cancel mutates forbidden state: {forbidden}"
        );
    }
}

#[test]
fn mobile_bridge_has_no_payment_signing_or_public_listener_and_wallet_fee_is_zero_only() {
    let module = [
        read("src-tauri/src/agent_companion/mod.rs"),
        read("src-tauri/src/agent_companion/commands.rs"),
        read("src-tauri/src/agent_companion/lifecycle.rs"),
        read("src-tauri/src/agent_companion/pairing.rs"),
        read("src-tauri/src/agent_companion/pilot.rs"),
        read("src-tauri/src/agent_companion/session.rs"),
        read("src-tauri/src/agent_companion/storage.rs"),
    ]
    .join("\n");
    for forbidden in [
        "wallet_send_hac",
        "wallet_send_hacd",
        "wallet_send_btc",
        "export_private_key",
        "TcpListener",
        "DesktopLanServer",
        "reqwest",
        "CompanionPayload::AdminCommand",
        "DeviceSignaturePurpose::AdminCommand",
        "signAdminCommand",
        "sign_arbitrary",
    ] {
        assert!(
            !module.contains(forbidden),
            "forbidden mobile surface {forbidden}"
        );
    }
    assert!(module.contains("approval.wallet_fee_units != 0"));
    assert!(module.contains("self.clear_pending_approval(&decision.operation_id)"));
    for required in [
        "CompanionPayload::ApprovalDecision",
        "CompanionPayload::WitnessReceipt",
        "agent_wallet_companion_decide_payment",
        "agent_wallet_companion_rotation_step",
        "agent_wallet_companion_witness_anchor",
        "require_pilot_enabled()?",
    ] {
        assert!(
            module.contains(required),
            "pilot surface missing {required}"
        );
    }
}

#[test]
fn android_signer_copies_match_and_allow_only_typed_pilot_authority() {
    let source =
        read("src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt");
    let generated_path = mobile_root().join(
        "src-tauri/gen/android/app/src/main/java/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt",
    );
    if generated_path.exists() {
        let generated = fs::read_to_string(&generated_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", generated_path.display()));
        assert_eq!(
            source, generated,
            "generated Android signer drifted from source"
        );
    }
    let rust = read("src-tauri/src/agent_companion_identity.rs");
    let compact_rust: String = rust
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();

    assert!(source.contains("companion authentication"));
    for required in [
        "signApprovalDecisionApprove",
        "signApprovalDecisionReject",
        "Approve this exact HPAY testnet payment",
        "Reject this exact HPAY testnet payment",
        "signWitnessReceipt",
        "APPROVAL_DECISION_DOMAIN",
        "WITNESS_RECEIPT_DOMAIN",
        "signWitnessRotationAuthorization",
        "signRotationCandidateAcceptance",
        "signWitnessRotationBaselineReceipt",
        "WITNESS_ROTATION_DOMAIN",
        "ROTATION_CANDIDATE_ACCEPTANCE_DOMAIN",
        "WITNESS_ROTATION_BASELINE_DOMAIN",
    ] {
        assert!(
            source.contains(required),
            "Android signer missing {required}"
        );
    }
    for forbidden in [
        "signAdminCommand",
        "ADMIN_COMMAND_DOMAIN",
        "fun sign(invoke:",
        "wallet_send_hac",
        "export_private_key",
    ] {
        assert!(
            !source.contains(forbidden),
            "Android signer exposes {forbidden}"
        );
    }
    // Everything that can end in money moving, or in a rollback witness
    // receipt, stays behind the pilot feature.
    for purpose in [
        "ApprovalDecision",
        "WitnessReceipt",
        "RotationCandidateAcceptance",
        "WitnessRotationBaselineReceipt",
    ] {
        assert!(compact_rust.contains(&format!(
            "DeviceSignaturePurpose::{purpose}ifcfg!(feature=\"agent-wallet-testnet-pilot\")=>"
        )));
    }
    // WitnessRotationAuthorization is deliberately not gated. It authorizes this
    // handset's own replacement, moves no money and signs no transaction, and
    // withholding it left a read-only build that had been marked as needing a
    // controlled rotation with no way to run one - a permanent dead end.
    assert!(
        compact_rust.contains("DeviceSignaturePurpose::WitnessRotationAuthorization=>"),
        "the old-phone rotation authorization must stay available in every build"
    );
    assert!(
        !compact_rust.contains(
            "DeviceSignaturePurpose::WitnessRotationAuthorizationifcfg!(feature=\"agent-wallet-testnet-pilot\")=>"
        ),
    );
    assert!(rust.contains("| DeviceSignaturePurpose::AdminCommand"));
    assert!(rust.contains("return Err(CompanionError::PermissionDenied)"));
}

#[test]
fn pilot_persists_monotonic_state_before_biometric_signing_and_never_auto_retries_money() {
    let pilot = read("src-tauri/src/agent_companion/pilot.rs");
    let session = read("src-tauri/src/agent_companion/session.rs");
    let decision = pilot
        .split_once("async fn sign_pilot_decision(")
        .expect("pilot decision signer")
        .1
        .split_once("async fn sign_pilot_witness(")
        .expect("pilot decision signer boundary")
        .0;
    assert!(
        decision.find("persist_locked(&next)").unwrap()
            < decision
                .find("agent_companion_identity::open(app)")
                .unwrap()
    );
    let witness = pilot
        .split_once("async fn sign_pilot_witness(")
        .expect("pilot witness signer")
        .1
        .split_once("async fn send_witness(")
        .expect("pilot witness signer boundary")
        .0;
    assert!(witness.contains("receipt_for_accepted_anchor"));
    assert!(
        witness.find("persist_locked(&next)").unwrap()
            < witness.find("agent_companion_identity::open(app)").unwrap()
    );
    let retry_safe = session
        .split_once("let retry_safe = matches!(")
        .expect("retry-safe payload gate")
        .1
        .split_once(";")
        .expect("retry-safe payload gate boundary")
        .0;
    assert!(retry_safe.contains("OutboundKind::Sync"));
    assert!(retry_safe.contains("OutboundKind::Ping"));
    assert!(retry_safe.contains("OutboundKind::RecoverPendingWitness"));
    assert!(!retry_safe.contains("OutboundKind::Approval"));
    assert!(!retry_safe.contains("OutboundKind::Witness"));
    assert!(pilot.contains("Approval transport is never replayed"));
    assert!(pilot.contains("recover_pending_proposal"));
}

#[test]
fn pairing_biometric_is_timeout_bounded_but_not_dropped_by_vendor_system_ui() {
    let pairing = read("src-tauri/src/agent_companion/pairing.rs");
    let manager = read("src-tauri/src/agent_companion/mod.rs");
    assert_eq!(pairing.matches("self.run_biometric_guarded(").count(), 3);
    assert!(!pairing.contains("self.run_guarded("));
    assert!(pairing.contains("PAIRING_TIMEOUT"));
    assert!(manager.contains("pub(super) async fn run_biometric_guarded"));
    assert!(manager.contains("tokio::time::timeout(limit, operation)"));
    assert!(manager.contains("let _lifecycle = self.lifecycle.lock().await"));
    assert!(manager.contains("lifecycle_signal_does_not_drop_an_active_hardware_biometric_result"));
    assert!(pairing.contains("Read-only pairing confirmation was rejected"));
}
