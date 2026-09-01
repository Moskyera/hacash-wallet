import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = dirname(fileURLToPath(import.meta.url));
const MOBILE = join(SRC, "..");

function read(relative: string): string {
  return readFileSync(join(MOBILE, relative), "utf8");
}

describe("Android private-screen hardening", () => {
  it("ships FLAG_SECURE from tracked source and validates the generated activity", () => {
    const activity = read(
      "src-tauri/android-src/org/hacash/wallet/mobile/MainActivity.kt",
    );
    const agentActivity = read(
      "src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionActivity.kt",
    );
    const applyScript = read("apply-android-patches.ps1");
    const validator = read("validate-android-build.ps1");

    expect(activity).toContain("WindowManager.LayoutParams.FLAG_SECURE");
    expect(agentActivity).toContain("WindowManager.LayoutParams.FLAG_SECURE");
    expect(agentActivity).toContain("class AgentCompanionActivity : TauriActivity()");
    expect(applyScript).toContain('$kotlinSrcRoot = Join-Path $mobile "src-tauri\\android-src"');
    expect(applyScript).toContain("Copy-Item $_.FullName $dst -Force");
    expect(validator).toContain("$mainActivitySource");
    expect(validator).toContain("$mainActivityGenerated");
    expect(validator).toContain("$agentActivitySource");
    expect(validator).toContain("$agentActivityGenerated");
    expect(validator).toContain("AndroidManifest must contain exactly one private AgentCompanionActivity");
    expect(validator).toContain("WindowManager\\.LayoutParams\\.FLAG_SECURE");
  });

  it("uses the frontend skip only before Android compilation", () => {
    const applyScript = read("apply-android-patches.ps1");
    const buildScript = read("build-android.ps1");
    const finishScript = read("finish-android-build.ps1");
    const validator = read("validate-android-build.ps1");
    const companionIdentity = read(
      "src-tauri/android-src/org/hacash/wallet/mobile/AgentCompanionIdentityPlugin.kt",
    );

    expect(validator).toContain("param([switch]$SkipEmbeddedFrontendCheck)");
    expect(validator).toContain(
      "if (-not $SkipEmbeddedFrontendCheck -and (Test-Path $jniLib) -and (Test-Path $distAssets))",
    );
    expect(applyScript).toContain(
      '& (Join-Path $mobile "validate-android-build.ps1") -SkipEmbeddedFrontendCheck',
    );
    expect(applyScript.match(/-SkipEmbeddedFrontendCheck/g)).toHaveLength(1);
    expect(buildScript).toContain(
      '& (Join-Path $mobile "validate-android-build.ps1")',
    );
    expect(buildScript).not.toContain("-SkipEmbeddedFrontendCheck");
    expect(finishScript).not.toContain("-SkipEmbeddedFrontendCheck");

    for (const domain of ["HPAY/COMPANION/ADMIN-COMMAND/V2"]) {
      expect(validator).toContain(domain);
      expect(companionIdentity).not.toContain(domain);
    }

    for (const domain of [
      "HPAY/COMPANION/PAIRING-REQUEST/V1",
      "HPAY/COMPANION/PAIRING-MOBILE-PROOF/V1",
      "HPAY/COMPANION/SESSION-RESPONSE/V1",
      "HPAY/COMPANION/APPROVAL-DECISION/V2",
      "HPAY/COMPANION/WITNESS-RECEIPT/V1",
      "HPAY/COMPANION/WITNESS-ROTATION/V1",
      "HPAY/COMPANION/WITNESS-ROTATION-BASELINE/V1",
    ]) {
      expect(validator).toContain(domain);
      expect(companionIdentity).toContain(domain);
    }
    expect(companionIdentity).toContain("fun signApprovalDecisionApprove(");
    expect(companionIdentity).toContain("fun signApprovalDecisionReject(");
    expect(companionIdentity).toContain(
      "HPAY/COMPANION/AGENT-FAST-PAY-DECISION/V1",
    );
    expect(companionIdentity).toContain(
      "fun signAgentFastPayApprovalDecisionApprove(",
    );
    expect(companionIdentity).toContain(
      "fun signAgentFastPayApprovalDecisionReject(",
    );
    expect(companionIdentity).toContain("fun signWitnessReceipt(");
    expect(companionIdentity).toContain("fun signWitnessRotationAuthorization(");
    expect(companionIdentity).toContain("fun signWitnessRotationBaselineReceipt(");
    expect(companionIdentity).not.toContain("fun signAdminCommand(");
  });
  it("keeps biometric unlock on the released bounded-window key policy", () => {
    const store = read(
      "src-tauri/android-src/org/hacash/wallet/mobile/BiometricSecretStore.kt",
    );
    const plugin = read(
      "src-tauri/android-src/org/hacash/wallet/mobile/WalletNativePlugin.kt",
    );
    const rust = read("src-tauri/src/lib.rs");

    expect(store).toContain('CURRENT_KEY_ALIAS = "hacash_wallet_biometric_unlock_v3"');
    expect(store).toContain('LEGACY_KEY_ALIAS = "hacash_wallet_biometric_unlock_v2"');

    // A stricter per-use, biometric-only key could not be enabled on device, so the
    // released v0.1.55 policy is in use. What still has to hold: the key requires
    // authentication, a new biometric enrolment invalidates it, and one
    // authentication covers a short, literal window rather than an open-ended one.
    expect(store).toContain("setUserAuthenticationRequired(true)");
    expect(store).toContain("setInvalidatedByBiometricEnrollment(true)");
    expect(store).toContain("AUTH_WINDOW_SECONDS = 30");
    expect(store).not.toMatch(/AUTH_WINDOW_SECONDS\s*=\s*\d{3}/);

    // Unlock accepts the device credential, which means the phone PIN or pattern
    // opens the wallet. Authorizing a send or Cold Vault activation must not: that
    // ceremony never touches the Keystore key, so nothing forces the fallback.
    expect(plugin).toContain(
      "private fun signingAuthenticators(): Int = BiometricManager.Authenticators.BIOMETRIC_STRONG",
    );
    expect(plugin).toContain("BiometricManager.Authenticators.DEVICE_CREDENTIAL");

    const unlockCeremony = plugin.slice(
      plugin.indexOf("private fun authenticateWithCipher("),
      plugin.indexOf("fun strongBiometricStatus("),
    );
    const signingCeremony = plugin.slice(plugin.indexOf("fun authenticateStrong("));
    expect(unlockCeremony).toContain(".setAllowedAuthenticators(unlockAuthenticators())");
    expect(unlockCeremony).not.toContain("signingAuthenticators()");
    expect(signingCeremony).toContain(".setAllowedAuthenticators(signingAuthenticators())");
    expect(signingCeremony).not.toContain("unlockAuthenticators()");

    // A negative button is mandatory without a credential fallback and rejected
    // with one, so it has to be derived from the authenticators actually allowed.
    expect(plugin).toContain(".withCancelButton(unlockAuthenticators())");
    expect(plugin).toContain(".withCancelButton(signingAuthenticators())");
    expect(plugin).toContain("if (activity !== this.activity) return");

    // A bounded-window key cannot be bound to a CryptoObject, so the prompt runs
    // first and the cipher is created afterwards.
    expect(plugin).toContain("prompt.authenticate(promptInfo)");
    expect(plugin).not.toContain("BiometricPrompt.CryptoObject(cipher)");

    // The Rust shell must never reuse a send-authorization prompt as the unlock or
    // enrolment ceremony.
    expect(rust).not.toContain(
      'verify_native_biometric(&app, "Unlock HPAY Wallet")',
    );
    expect(rust).not.toContain(
      'verify_native_biometric(&app, "Enable biometric unlock for HPAY Wallet")',
    );
  });

  it("rejects update APKs with a different package or signer before ACTION_VIEW", () => {
    const installer = read(
      "src-tauri/android-src/org/hacash/wallet/mobile/ApkInstaller.kt",
    );

    expect(installer).toContain("verifyPackageIdentityAndSigner(activity, source)");
    expect(installer).toContain("PackageManager.GET_SIGNING_CERTIFICATES");
    expect(installer).toContain("candidate.packageName != activity.packageName");
    expect(installer).toContain('MessageDigest.getInstance("SHA-256")');
    expect(installer).toContain(".intersect(installedIdentity.currentCertificateSha256)");
    expect(installer.indexOf("verifyPackageIdentityAndSigner(activity, source)"))
      .toBeLessThan(installer.indexOf("Intent(Intent.ACTION_VIEW)"));
  });

  it("locks and conceals on background while clearing wallet clipboard data", () => {
    const app = read("src/MobileApp.tsx");

    expect(app).toContain('document.addEventListener("visibilitychange", onVisibilityChange)');
    expect(app).toContain('window.addEventListener("pagehide", lockForBackground)');
    expect(app).toContain("void clearSensitiveClipboard()");
    expect(app).toContain(".lock()");
    expect(app).toContain("<PrivacyShield active={privacyHidden} />");
  });

  it("never uses a production send authorization as a biometric test", () => {
    const securityScreen = read("src/screens/more/SecurityScreen.tsx");

    expect(securityScreen).not.toContain(".confirmBiometric()");
    expect(securityScreen).not.toContain('t("security.testBiometric")');
    expect(securityScreen).toContain('t("security.paranoidDesktopOnly")');
    expect(securityScreen).not.toContain('.setSecurityProfile("paranoid"');
  });

  it("removes Android biometric unlock before Cold Vault activation", () => {
    const mobileRust = read("src-tauri/src/lib.rs");
    const commonCommands = read("../../crates/wallet-tauri-common/src/commands.rs");
    const prepared = read("../../crates/wallet-tauri-common/src/prepared_commands.rs");

    expect(mobileRust).toContain(
      'if svc.get_settings().hardware_signing_mode == "airgap_only"',
    );
    expect(mobileRust).toContain('if signing_policy == "airgap_only"');
    expect(mobileRust).toContain("biometric_store::clear(&app).await");

    // The passphrase-only entrypoint must refuse Cold Vault outright.
    const coldStart = commonCommands.indexOf("if hw == HardwareSigningMode::AirgapOnly");
    const migrationStart = commonCommands.indexOf("svc.change_hardware_signing_mode", coldStart);
    const coldBranch = commonCommands.slice(coldStart, migrationStart);
    expect(coldStart).toBeGreaterThanOrEqual(0);
    expect(coldBranch).toContain("return Err(");
    expect(coldBranch).not.toContain("clear_native_biometric_secret");

    // Activation lives behind the prepared ceremony, and the OS unlock secret is
    // deleted only after that ceremony is confirmed and before the migration.
    const activation = prepared.slice(
      prepared.indexOf("pub async fn wallet_execute_prepared_cold_vault_activation("),
    );
    expect(activation.indexOf("cold_vault_activation_is_authorized")).toBeGreaterThanOrEqual(0);
    expect(activation.indexOf("clear_native_biometric_secret(&app).await?")).toBeGreaterThan(
      activation.indexOf("cold_vault_activation_is_authorized"),
    );
    expect(activation.indexOf("execute_prepared_cold_vault_activation(&operation_id")).toBeGreaterThan(
      activation.indexOf("clear_native_biometric_secret(&app).await?"),
    );
  });

  it("activates Cold Vault only through the prepared ceremony", () => {
    const securityScreen = read("src/screens/more/SecurityScreen.tsx");

    expect(securityScreen).not.toContain('.setHardwareMode("airgap_only"');
    expect(securityScreen).toContain("api.prepareColdVaultActivation()");
    expect(securityScreen).toContain("api.confirmBiometric(prepared.id)");
    expect(securityScreen).toContain(
      "api.executePreparedColdVaultActivation(prepared.id, passphrase)",
    );
    // Mobile cannot run a WebAuthn ceremony, so a WebAuthn-bound vault must be
    // told to activate on desktop rather than silently downgrading the factor.
    expect(securityScreen).toContain("prepared.webauthn_required");
  });

  it("keeps Cold Vault in signer-only mode and gates a second signature", () => {
    const airgap = read("src/components/AirgapScreen.tsx");

    expect(airgap).toContain("disabled={coldVault}");
    expect(airgap).toContain('{mode === "coordinator" && !coldVault && (');
    expect(airgap).toContain(
      '{mode === "signer" && !watchOnly && signingAvailable && (',
    );
    expect(airgap).toContain('{t("security.lockWallet")}');
  });
});
