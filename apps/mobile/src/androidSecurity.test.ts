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
    const applyScript = read("apply-android-patches.ps1");
    const validator = read("validate-android-build.ps1");

    expect(activity).toContain("WindowManager.LayoutParams.FLAG_SECURE");
    expect(applyScript).toContain('$kotlinSrcRoot = Join-Path $mobile "src-tauri\\android-src"');
    expect(applyScript).toContain("Copy-Item $_.FullName $dst -Force");
    expect(validator).toContain("$mainActivitySource");
    expect(validator).toContain("$mainActivityGenerated");
    expect(validator).toContain("WindowManager\\.LayoutParams\\.FLAG_SECURE");
  });

  it("binds every biometric unlock decrypt to an auth-per-use CryptoObject", () => {
    const store = read(
      "src-tauri/android-src/org/hacash/wallet/mobile/BiometricSecretStore.kt",
    );
    const plugin = read(
      "src-tauri/android-src/org/hacash/wallet/mobile/WalletNativePlugin.kt",
    );
    const rust = read("src-tauri/src/lib.rs");

    expect(store).toContain('CURRENT_KEY_ALIAS = "hacash_wallet_biometric_unlock_v3"');
    expect(store).toContain('LEGACY_KEY_ALIAS = "hacash_wallet_biometric_unlock_v2"');
    expect(store).toContain(
      "setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)",
    );
    expect(store).toContain("setUserAuthenticationValidityDurationSeconds(-1)");
    expect(store).not.toContain("AUTH_WINDOW_SECONDS");
    expect(plugin).toContain(
      "private fun authenticators(): Int = BiometricManager.Authenticators.BIOMETRIC_STRONG",
    );
    expect(plugin).not.toContain("BiometricManager.Authenticators.DEVICE_CREDENTIAL");
    expect(plugin).toContain(
      "prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))",
    );
    expect(plugin).toContain("BiometricSecretStore.prepareEncryption(activity)");
    expect(plugin).toContain("BiometricSecretStore.prepareDecryption(activity)");
    expect(rust).not.toContain(
      'verify_native_biometric(&app, "Unlock Hacash Wallet")',
    );
    expect(rust).not.toContain(
      'verify_native_biometric(&app, "Enable biometric unlock for Hacash Wallet")',
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
    const coldStart = commonCommands.indexOf("if hw == HardwareSigningMode::AirgapOnly");
    const migrationStart = commonCommands.indexOf(
      "svc.change_hardware_signing_mode",
      coldStart,
    );
    const coldBranch = commonCommands.slice(coldStart, migrationStart);

    expect(mobileRust).toContain(
      'if svc.get_settings().hardware_signing_mode == "airgap_only"',
    );
    expect(mobileRust).toContain('if signing_policy == "airgap_only"');
    expect(mobileRust).toContain("biometric_store::clear(&app).await");
    expect(coldStart).toBeGreaterThanOrEqual(0);
    expect(coldBranch).toContain("verify_wallet_passphrase(&current_passphrase)");
    expect(coldBranch).toContain("clear_native_biometric_secret(&app).await?");
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
