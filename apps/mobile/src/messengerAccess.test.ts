import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { messengerBlockedReason } from "./messengerAccess";
import type { WalletStatus } from "./api";

const HERE = dirname(fileURLToPath(import.meta.url));

function status(over: Partial<WalletStatus> = {}): WalletStatus {
  return {
    has_wallet: true,
    locked: false,
    address: "1abc",
    security_profile: "standard",
    node_url: "http://127.0.0.1:8080",
    network_mode: "testnet",
    l2_enabled: false,
    fast_pay_state: "idle",
    fast_pay_message: "",
    legacy_key_derivation: null,
    watch_only: false,
    privacy: {} as WalletStatus["privacy"],
    seconds_until_lock: null,
    channel_id: null,
    hardware_signing_mode: "software",
    require_second_factor_above_mei: 0,
    signing_available: true,
    ...over,
  };
}

describe("the companion phone opening Messages", () => {
  it("declines before it asks, on a wallet with no signing key here", () => {
    expect(messengerBlockedReason(status({ watch_only: true }))).toMatch(/watch-only/i);
    expect(messengerBlockedReason(status({ hardware_signing_mode: "airgap_only" }))).toMatch(
      /Cold Vault/,
    );
    expect(messengerBlockedReason(status({ locked: true }))).toMatch(/unlock/i);
    expect(messengerBlockedReason(null)).toMatch(/unlock/i);
  });

  it("lets an ordinary unlocked wallet straight through", () => {
    expect(messengerBlockedReason(status())).toBeNull();
  });

  it("never names an operation that does not exist for messages", () => {
    // The raw policy string the person used to be shown told them to use "a
    // freshly authorized prepared Type 2 air-gap operation", which opens no
    // message store anywhere in this wallet.
    for (const s of [
      status({ watch_only: true }),
      status({ hardware_signing_mode: "airgap_only" }),
      status({ locked: true }),
    ]) {
      const reason = messengerBlockedReason(s) ?? "";
      expect(reason).not.toMatch(/type 2/i);
      expect(reason).not.toMatch(/air-gap operation/i);
      expect(reason).not.toMatch(/security policy blocked/i);
    }
  });

  it("is wired into the screen, and the screen is given the status to ask with", () => {
    const screen = readFileSync(join(HERE, "components/MessengerScreen.tsx"), "utf8");
    expect(screen).toMatch(/messengerBlockedReason\(status\)/);
    // The refresh and the fifteen-second poll both stand down when blocked,
    // which is what stopped the repeating toast.
    expect(screen).toMatch(/if \(blocked\) return;/);
    expect(screen).toMatch(/if \(blocked \|\| !whisperEnabled\) return;/);
    const router = readFileSync(join(HERE, "screens/more/MoreRouter.tsx"), "utf8");
    expect(router).toMatch(/status=\{status\}/);
  });
});
