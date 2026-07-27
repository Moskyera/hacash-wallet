import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = dirname(fileURLToPath(import.meta.url));

function read(relative: string): string {
  return readFileSync(join(SRC, relative), "utf8");
}

describe("destructive wallet IPC", () => {
  it("always sends both reset authentication fields", () => {
    const api = read("api.ts");

    expect(api).toContain(
      'resetWallet: (currentPassphrase: string | null, confirmationAddress: string)',
    );
    expect(api).toContain(
      'invoke<void>("wallet_reset", { currentPassphrase, confirmationAddress })',
    );
    expect(api).not.toContain('resetWallet: () => invoke<void>("wallet_reset")');
  });

  it("requires exact address confirmation and a passphrase for signing wallets", () => {
    const screen = read("screens/more/SecurityScreen.tsx");

    expect(screen).toContain('const [resetPassphrase, setResetPassphrase] = useState("")');
    expect(screen).toContain('const [resetAddress, setResetAddress] = useState("")');
    expect(screen).toContain("resetAddress !== status.address");
    expect(screen).toContain("(!watchOnly && !resetPassphrase)");
    expect(screen).toContain("watchOnly ? null : resetPassphrase");
    expect(screen).toContain("onResetWallet(passphrase, address)");
    expect(screen).not.toContain("busy ||\n            watchOnly ||");
    expect(screen).not.toContain("onClick={onResetWallet}");
  });

  it("does not treat a browser confirmation as reset authorization", () => {
    const app = read("MobileApp.tsx");
    const resetHandler = app
      .split("const handleResetWallet = async", 2)[1]
      ?.split("const handleSaveSettings", 1)[0];

    expect(resetHandler).toBeTruthy();
    expect(resetHandler).not.toContain("window.confirm");
    expect(resetHandler).toContain(
      "api.resetWallet(currentPassphrase, confirmationAddress)",
    );
  });

  // Closing a Fast Pay channel signs a real settlement, so it belongs in the prepared
  // ceremony. The unprepared api.closeChannel() can never succeed anyway: the core
  // passes the second-factor threshold itself as the policed amount, so the requirement
  // is never None and the call is always refused. A control that always errors is worse
  // than no control, because the working one lives on another screen.
  it("closes a Fast Pay channel through the prepared ceremony, not the dead path", () => {
    const session = read("hooks/useWalletSession.ts");

    const disable = session
      .split("const handleDisableFastPay = useCallback", 2)[1]
      ?.split("const handleClearHistory", 1)[0];

    expect(disable).toBeTruthy();
    expect(disable).toContain("api.prepareChannelClose()");
    expect(disable).toContain("authorizePreparedOperation(");
    expect(disable).toContain("api.executePreparedChannelClose(prepared.id)");
    expect(disable).not.toContain("api.closeChannel()");
  });

  it("surfaces the biometric cleanup result after a passphrase change", () => {
    const app = read("MobileApp.tsx");

    expect(app).toContain("outcome.nativeBiometricSecretCleared");
    expect(app).toContain("biometric unlock was disabled");
    expect(app).toContain("retry Android Keystore cleanup");
  });
  // Every screen that states or acts on the confirmation amount must read what the core
  // reports, never a constant of its own. The constant is the balanced default, so a
  // screen using it would quietly ignore a user who tightened the policy, and the send
  // routing would pick a rail the core then refuses.
  it("reads the confirmation amount from the core, not from a constant", () => {
    const security = read("screens/more/SecurityScreen.tsx");
    const payTab = read("screens/PayTab.tsx");
    const flow = read("hooks/usePaymentFlow.ts");

    expect(security).toContain("status?.require_second_factor_above_mei ??");
    expect(security).toContain("amount: enforcedThreshold - 1");
    expect(security).not.toContain("amount: BIOMETRIC_THRESHOLD_MEI");

    expect(payTab).toContain("secondFactorThresholdMei,");
    expect(payTab).not.toContain("BIOMETRIC_THRESHOLD_MEI");

    expect(flow).toContain("secondFactorThresholdMei,");
  });

  // Raising the amount widens the range of payments that need no confirmation, so it is
  // a policy change and needs the passphrase. The generic settings command must not be
  // able to carry it.
  it("changes the confirmation amount only through the authenticated command", () => {
    const api = read("api.ts");
    const security = read("screens/more/SecurityScreen.tsx");

    expect(api).toContain(
      'invoke<void>("wallet_set_second_factor_threshold", { amountMei, currentPassphrase })',
    );
    expect(security).toContain(".setSecondFactorThreshold(amount, passphrase)");
    expect(security).toContain(".setSecondFactorThreshold(null, passphrase)");
    // The control must collect the passphrase, not send an empty one.
    expect(security).toContain("disabled={busy || !thresholdPassphrase || !thresholdDraft}");
  });
  // Third time this bug class appears: a screen decides from its own copy of the
  // threshold while the core has moved on. The constant may only be a fallback inside
  // the shared gate helper and the one screen that displays it; no other file may
  // compare an amount against a literal threshold.
  it("has no screen deciding a second factor from a hardcoded amount", () => {
    const gate = read("utils/secondFactorGate.ts");
    const quantum = read("components/QuantumScreen.tsx");

    // The gate is the only place allowed to fall back to the constant.
    expect(gate).toContain("BIOMETRIC_THRESHOLD_MEI");
    expect(gate).toContain("thresholdMei");

    // Quantum sends are policed by the same rule, so its gate needs the same inputs.
    expect(quantum).toContain("needsSecondFactor(amount, securityProfile, hardwareMode, secondFactorThresholdMei)");
    expect(quantum).not.toContain(">= 100");

    // Fast Pay cannot carry authorization, so a protected amount is refused rather than
    // prompted. Promising a fingerprint there would only be discovered after tapping.
    //
    // Assert the distinctive sentence, not the word "Force": that word already appears in
    // the Force on-chain checkbox label and inside sendForceL1, so it passes even if the
    // whole refusal paragraph is deleted.
    const payTab = read("screens/PayTab.tsx");
    expect(payTab).toContain('preview.plan.rail === "L2Fast" ? (');
    expect(payTab).toContain("Fast Pay cannot be confirmed");
    expect(payTab).toContain("on-chain (L1) above to pay it");
  });
});
