import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clearSystemDialogExpectation,
  expectSystemDialog,
  systemDialogInFlight,
} from "./systemDialogGuard";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

function read(relative: string): string {
  return readFileSync(join(SRC, relative), "utf8");
}

afterEach(() => {
  vi.useRealTimers();
  clearSystemDialogExpectation();
});

describe("system dialog guard", () => {
  it("is closed unless something opened it", () => {
    expect(systemDialogInFlight()).toBe(false);
  });

  it("expires on its own, so a dialog that never resolves cannot hold it open", () => {
    vi.useFakeTimers();
    expectSystemDialog(15_000);
    expect(systemDialogInFlight()).toBe(true);

    vi.advanceTimersByTime(14_999);
    expect(systemDialogInFlight()).toBe(true);

    vi.advanceTimersByTime(2);
    expect(systemDialogInFlight()).toBe(false);
  });

  it("closes immediately when the app is in the foreground again", () => {
    expectSystemDialog(15_000);
    clearSystemDialogExpectation();
    expect(systemDialogInFlight()).toBe(false);
  });

  // The camera permission dialog runs as a separate activity, so the WebView sees
  // visibilitychange "hidden" and the wallet used to lock and drop the user on the unlock
  // screen mid-scan. Only the lock is deferred: concealing, clearing the passphrase field
  // and wiping the clipboard must still happen, or the recents list would leak.
  it("defers only the lock, never the concealment", () => {
    const app = read("MobileApp.tsx");
    const lock = app
      .split("const lockForBackground = () => {", 2)[1]
      ?.split("const onVisibilityChange", 1)[0];

    expect(lock).toBeTruthy();
    const conceal = lock!.indexOf("setPrivacyHidden(true)");
    const clearPass = lock!.indexOf('setPassphrase("")');
    const clipboard = lock!.indexOf("clearSensitiveClipboard()");
    const guard = lock!.indexOf("systemDialogInFlight()");
    const lockCall = lock!.indexOf("api\n        .lock()");

    expect(conceal).toBeGreaterThanOrEqual(0);
    expect(guard).toBeGreaterThan(conceal);
    expect(guard).toBeGreaterThan(clearPass);
    expect(guard).toBeGreaterThan(clipboard);
    expect(lockCall).toBeGreaterThan(guard);
  });

  // A wallet must not switch the camera on by itself, and doing so used to raise the
  // Android permission dialog before the user had chosen to scan anything.
  it("never starts the camera without the user asking", () => {
    const app = read("MobileApp.tsx");
    const payTab = read("screens/PayTab.tsx");
    const base = read("components/QrScannerBase.tsx");

    expect(app).not.toContain("setPayCameraIntent");
    expect(payTab).not.toContain("autoStart");
    // The scanner offers its own control instead.
    expect(base).not.toContain("autoStart");
    expect(base).toContain("Open camera");
    // Starting it must arm the guard, or granting the permission locks the wallet.
    expect(base).toContain("expectSystemDialog()");
  });
});
