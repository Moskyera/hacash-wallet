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
});
