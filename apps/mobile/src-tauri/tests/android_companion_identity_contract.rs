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
fn companion_identity_is_a_dedicated_non_exportable_keystore_key() {
    let kotlin =
        read("src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt");
    for contract in [
        "hpay_agent_companion_identity_v1",
        "KeyProperties.KEY_ALGORITHM_EC",
        "ECGenParameterSpec(\"secp256r1\")",
        "KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY",
        "setUserAuthenticationRequired(true)",
        "setInvalidatedByBiometricEnrollment(true)",
        "setUserAuthenticationParameters(",
        "KeyProperties.AUTH_BIOMETRIC_STRONG",
        "setUserAuthenticationValidityDurationSeconds(-1)",
        "entry.privateKey.encoded == null",
        "BiometricPrompt.CryptoObject(preparedSignature)",
        "authorizedSignature !== preparedSignature",
        "authorizedSignature.update(pending.canonicalPayload)",
        "info.userAuthenticationValidityDurationSeconds == 0",
        "info.userAuthenticationValidityDurationSeconds == -1",
        "info.userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG",
        "info.keySize == 256",
        "info.purposes == expectedPurposes",
        "info.digests.toSet() == setOf(KeyProperties.DIGEST_SHA256)",
        "info.isInvalidatedByBiometricEnrollment",
        "publicKey.params.order == P256_ORDER",
        "KeyPermanentlyInvalidatedException",
        "recreateIdentity(store)",
        "destroyed.get() ||",
        "activeSignature !== pending ||",
    ] {
        assert!(
            kotlin.contains(contract),
            "Android companion identity contract missing {contract}"
        );
    }
    for forbidden in [
        "DEVICE_CREDENTIAL",
        "wallet_send_hac",
        "PrivateKeyEntry.privateKey.encoded.to",
        "fun sign(invoke:",
        "fun signAdminCommand(",
        "HPAY/COMPANION/ADMIN-COMMAND/V2",
        "put(\"authPerUse\", true)",
        "fun signSessionChallenge(",
        "fun signSessionConfirmation(",
    ] {
        assert!(
            !kotlin.contains(forbidden),
            "Android companion identity contains forbidden surface {forbidden}"
        );
    }
}

#[test]
fn biometric_prompt_is_bound_to_the_resumed_private_agent_activity() {
    let activity = read("src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionActivity.kt");
    let plugin =
        read("src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt");

    for contract in [
        "WeakReference<AgentCompanionActivity>",
        "fun currentResumed(): AgentCompanionActivity?",
        "Lifecycle.State.RESUMED",
        "clearResumed(this)",
    ] {
        assert!(
            activity.contains(contract),
            "Agent Activity lifecycle missing {contract}"
        );
    }
    for contract in [
        "AgentCompanionActivity.currentResumed()",
        "ContextCompat.getMainExecutor(fragmentActivity)",
        "activity !== this.activity && activity !is AgentCompanionActivity",
        "The Agent Wallet is not in the foreground",
    ] {
        assert!(
            plugin.contains(contract),
            "biometric Activity binding missing {contract}"
        );
    }
    assert!(!plugin.contains("activity as? FragmentActivity"));
}

#[test]
fn native_plugin_only_signs_known_domain_separated_companion_payloads() {
    let kotlin =
        read("src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt");
    for domain in [
        "HPAY/COMPANION/PAIRING-REQUEST/V1",
        "HPAY/COMPANION/PAIRING-MOBILE-PROOF/V1",
        "HPAY/COMPANION/SESSION-RESPONSE/V1",
        "HPAY/COMPANION/APPROVAL-DECISION/V2",
        "HPAY/COMPANION/WITNESS-RECEIPT/V1",
        "HPAY/COMPANION/WITNESS-ROTATION/V1",
        "HPAY/COMPANION/ROTATION-CANDIDATE-ACCEPTANCE/V1",
        "HPAY/COMPANION/WITNESS-ROTATION-BASELINE/V1",
    ] {
        assert!(kotlin.contains(domain), "missing canonical domain {domain}");
    }
    for command in [
        "fun signPairingRequest(",
        "fun signPairingMobileProof(",
        "fun signSessionResponse(",
        "fun signApprovalDecisionApprove(",
        "fun signApprovalDecisionReject(",
        "fun signWitnessReceipt(",
        "fun signWitnessRotationAuthorization(",
        "fun signRotationCandidateAcceptance(",
        "fun signWitnessRotationBaselineReceipt(",
    ] {
        assert!(kotlin.contains(command), "missing typed command {command}");
    }
    assert!(kotlin.contains("hasCanonicalDomain(payload, expectedDomain)"));
    assert!(kotlin.contains("MAX_CANONICAL_PAYLOAD_BYTES = 256 * 1024"));
    assert!(kotlin.contains("MAX_CANONICAL_PAYLOAD_BASE64_CHARS"));
    assert!(kotlin.contains("encodedPayload.length > MAX_CANONICAL_PAYLOAD_BASE64_CHARS"));
}

#[test]
fn rust_adapter_has_no_js_command_or_personal_wallet_dependency() {
    let rust = read("src-tauri/src/agent_companion_identity.rs");
    let compact_rust: String = rust
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect();
    let mobile_lib = read("src-tauri/src/lib.rs");
    assert!(rust.contains("impl<R: Runtime> PlatformDeviceSigner"));
    assert!(rust.contains("DeviceSignaturePurpose::PairingConfirmation"));
    assert!(rust.contains("DeviceSignaturePurpose::PairingMobileProof"));
    assert!(rust.contains("DeviceSignaturePurpose::SessionChallenge"));
    assert!(rust.contains("DeviceSignaturePurpose::SessionResponse"));
    assert!(rust.contains("DeviceSignaturePurpose::SessionConfirmation"));
    assert!(rust.contains("\"signPairingMobileProof\""));
    assert!(rust.contains("\"signSessionResponse\""));
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
    // WitnessRotationAuthorization is deliberately available in every build: it
    // authorizes this handset's own replacement, spends nothing and signs no
    // transaction. Gating it left a read-only build marked as needing a
    // controlled rotation with no way to run one.
    assert!(compact_rust.contains("DeviceSignaturePurpose::WitnessRotationAuthorization=>"));
    assert!(!compact_rust.contains(
        "DeviceSignaturePurpose::WitnessRotationAuthorizationifcfg!(feature=\"agent-wallet-testnet-pilot\")=>"
    ));
    assert!(rust.contains("\"signApprovalDecisionApprove\""));
    assert!(rust.contains("\"signApprovalDecisionReject\""));
    assert!(rust.contains("MobileApprovalDecision::from_canonical_bytes"));
    assert!(rust.contains("\"signWitnessReceipt\""));
    assert!(rust.contains("\"signWitnessRotationAuthorization\""));
    assert!(rust.contains("\"signRotationCandidateAcceptance\""));
    assert!(rust.contains("\"signWitnessRotationBaselineReceipt\""));
    assert!(rust.contains("return Err(CompanionError::PermissionDenied)"));
    let purpose_gate = rust
        .find("let operation = match purpose")
        .expect("typed purpose gate");
    let kotlin_call = rust
        .find("let response = handle(app)")
        .expect("Kotlin call");
    assert!(
        purpose_gate < kotlin_call,
        "desktop-only purposes must fail before the Kotlin bridge"
    );
    assert!(!rust.contains("#[tauri::command]"));
    assert!(!rust.contains("WalletService"));
    assert!(!rust.contains("wallet_send"));
    assert!(!rust.contains("PersonalWallet"));
    assert!(!rust.contains("wallet_private"));
    assert!(mobile_lib.contains("agent_companion_identity::init()"));
}

#[test]
fn companion_webview_cannot_invoke_signing_or_private_key_operations() {
    let capability = read("src-tauri/capabilities/agent-companion.json");
    let permissions = read("src-tauri/permissions/wallet.toml");
    let frontend = read("src/agent/api.ts");
    let agent_permission = permissions
        .split("[[permission]]")
        .find(|section| section.contains("identifier = \"allow-agent-companion\""))
        .expect("allow-agent-companion permission");

    assert!(capability.contains("\"local\": true"));
    assert!(capability.contains("\"webviews\": [\"agent-companion\"]"));
    assert!(agent_permission.contains("agent_wallet_companion_identity_status"));
    assert!(agent_permission.contains("agent_wallet_companion_create_identity"));
    for forbidden in [
        "signPairingRequest",
        "signPairingMobileProof",
        "signSessionResponse",
        "signApprovalDecision",
        "signAdminCommand",
        "private_key",
        "wallet_send",
    ] {
        assert!(
            !capability.contains(forbidden),
            "capability exposes forbidden companion operation {forbidden}"
        );
        assert!(
            !agent_permission.contains(forbidden),
            "permission exposes forbidden companion operation {forbidden}"
        );
        assert!(
            !frontend.contains(forbidden),
            "frontend exposes forbidden companion operation {forbidden}"
        );
    }
}

fn quoted_literal_after<'a>(source: &'a str, marker: &str) -> &'a str {
    let tail = source
        .split_once(marker)
        .unwrap_or_else(|| panic!("missing domain declaration {marker}"))
        .1;
    let quoted = tail
        .split_once('"')
        .unwrap_or_else(|| panic!("missing opening quote after {marker}"))
        .1;
    quoted
        .split_once('"')
        .unwrap_or_else(|| panic!("missing closing quote after {marker}"))
        .0
}

#[test]
fn android_signing_domains_match_the_protocol_crate_exactly() {
    let kotlin =
        read("src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt");
    for (rust_path, rust_marker, kotlin_marker) in [
        (
            "../../crates/companion-protocol/src/pairing.rs",
            "const PAIRING_REQUEST_DOMAIN: &[u8] = b",
            "private val PAIRING_REQUEST_DOMAIN =",
        ),
        (
            "../../crates/companion-protocol/src/pairing/proof.rs",
            "const PROOF_DOMAIN: &[u8] = b",
            "private val PAIRING_MOBILE_PROOF_DOMAIN =",
        ),
        (
            "../../crates/companion-protocol/src/session/types.rs",
            "const RESPONSE_DOMAIN: &[u8] = b",
            "private val SESSION_RESPONSE_DOMAIN =",
        ),
        (
            "../../crates/companion-protocol/src/approval.rs",
            "const DECISION_DOMAIN: &[u8] = b",
            "private val APPROVAL_DECISION_DOMAIN =",
        ),
        (
            "../../crates/companion-protocol/src/witness.rs",
            "const RECEIPT_DOMAIN: &[u8] = b",
            "private val WITNESS_RECEIPT_DOMAIN =",
        ),
    ] {
        let rust = read(rust_path);
        assert_eq!(
            quoted_literal_after(&rust, rust_marker),
            quoted_literal_after(&kotlin, kotlin_marker),
            "Android native signer domain drifted from {rust_path}"
        );
    }
}
#[test]
fn biometric_failure_releases_the_signing_slot_and_zeroizes_the_payload() {
    let kotlin =
        read("src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt")
            .replace("\r\n", "\n");
    let auth_error = kotlin
        .split_once("override fun onAuthenticationError(")
        .expect("biometric failure callback")
        .1
        .split_once("    }\n    try {")
        .expect("biometric failure callback boundary")
        .0;
    assert!(auth_error.contains("finishSignature(pending)"));
    assert!(auth_error.contains("pending.reject("));
    assert!(!auth_error.contains("pending.resolve("));

    let finish = kotlin
        .split_once("private fun finishSignature(")
        .expect("signature cleanup helper")
        .1
        .split_once("  override fun onDestroy(")
        .expect("signature cleanup helper boundary")
        .0;
    assert!(finish.contains("activePrompt = null"));
    assert!(finish.contains("activeSignature = null"));
    assert!(finish.find("activeSignature = null").unwrap() < finish.find("finish()").unwrap());

    let reject = kotlin
        .split_once("fun reject(message: String)")
        .expect("pending rejection")
        .1
        .split_once("  }\n\n  private enum class")
        .expect("pending rejection boundary")
        .0;
    assert!(reject.contains("canonicalPayload.fill(0)"));
}

#[test]
fn android_pairing_diagnostics_report_only_bounded_stages() {
    let kotlin =
        read("src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt");
    for contract in [
        "private const val LOG_TAG = \"HPAYAgentIdentity\"",
        "sign request accepted: $description",
        "Keystore signature prepared: $description",
        "biometric prompt requested: $description",
        "biometric callback succeeded: $description",
        "biometric callback error code=$errorCode: $description",
    ] {
        assert!(
            kotlin.contains(contract),
            "native diagnostic missing {contract}"
        );
    }
    for line in kotlin.lines().filter(|line| line.contains("Log.")) {
        let lower = line.to_ascii_lowercase();
        for forbidden in [
            "payloadbase64",
            "canonicalpayload",
            "signatureder",
            "verification_code",
            "pairing_id",
            "device_id",
            "wallet_id",
        ] {
            assert!(
                !lower.contains(forbidden),
                "native diagnostic leaks forbidden field {forbidden}: {line}"
            );
        }
    }
}
