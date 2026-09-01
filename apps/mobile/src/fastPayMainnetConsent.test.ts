import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  FAST_PAY_MAINNET_CEILINGS,
  FAST_PAY_MAINNET_CONSENT,
} from "@hacash/wallet-ui";

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (path: string) => readFileSync(join(HERE, path), "utf8");

const SCREENS = {
  mobile: "screens/FastPayChannelScreen.tsx",
  desktop: "../../desktop/src/screens/FastPayScreen.tsx",
};

describe("mobile bounded mainnet Fast Pay consent", () => {
  it("is explicit, persisted and required before channel funding", () => {
    const screen = read(SCREENS.mobile);
    const api = read("api.ts");

    expect(api).toContain("trusted_mainnet_fast_pay_pilot: boolean");
    expect(screen).toContain("Bounded mainnet pilot");
    expect(screen).toContain("api.updateSettings");
    expect(screen).toContain("!settings.trusted_mainnet_fast_pay_pilot");
    expect(screen).toContain("Channel recovery remains available");
  });
});

describe("the words before mainnet money", () => {
  it("names how the money is actually lost on the rail this consent governs", () => {
    // "Fast Pay depends on the selected Hub and is not a trustless L1 exit" is
    // true and tells a person nothing.
    //
    // What replaced it was borrowed from the wrong rail. It described a Hub
    // putting an old receipt on chain during a challenge window, which is an
    // HVM registry story. Mainnet Fast Pay is native ChannelPay, where
    // `channel_close` checks BOTH signatures and no challenge action exists,
    // so a Hub acting alone cannot move the money at all.
    //
    // The real risk is the mirror image: the money only comes out if the Hub
    // co-signs. These assertions pin that, and forbid the registry story
    // coming back to a screen it does not describe.
    expect(FAST_PAY_MAINNET_CONSENT).toMatch(/only be closed if the Hub co-signs/);
    expect(FAST_PAY_MAINNET_CONSENT).toMatch(/no way for me to get this money out on my own/);
    expect(FAST_PAY_MAINNET_CONSENT).toMatch(/requires both signatures/);
    expect(FAST_PAY_MAINNET_CONSENT).toMatch(/stays locked/);
    expect(FAST_PAY_MAINNET_CONSENT).not.toMatch(/old receipt/);
    expect(FAST_PAY_MAINNET_CONSENT).not.toMatch(/challenge window/);
  });

  it("offers the ceilings as ceilings, not as the limits a person gets", () => {
    // The only Hub ever measured against mainnet declared a hundredth of
    // these. Somebody sizing a deposit against "10 HAC per channel" would be
    // reading a compile-time constant rather than their Hub's answer.
    expect(FAST_PAY_MAINNET_CEILINGS).toMatch(/1 HAC per payment/);
    expect(FAST_PAY_MAINNET_CEILINGS).toMatch(/10 HAC per channel/);
    expect(FAST_PAY_MAINNET_CEILINGS).toMatch(/100 HAC total TVL/);
    expect(FAST_PAY_MAINNET_CEILINGS).toMatch(/No Hub may exceed/);
    expect(FAST_PAY_MAINNET_CEILINGS).toMatch(/not the limits you get/);
    expect(FAST_PAY_MAINNET_CEILINGS).toMatch(/What your Hub declares is what applies/);
  });

  for (const [which, path] of Object.entries(SCREENS)) {
    it(`the ${which} screen renders the shared words rather than its own`, () => {
      const screen = read(path);
      // Rendered, in JSX braces. Importing a constant and displaying a
      // different sentence beside it is how the Agent Wallet shipped a consent
      // whose own acknowledgement was never once on screen.
      expect(screen).toMatch(/\{FAST_PAY_MAINNET_CEILINGS\}/);
      expect(screen).toMatch(/\{FAST_PAY_MAINNET_CONSENT\}/);
      // And the opaque wording they replaced is gone from both.
      expect(screen).not.toMatch(/I understand the Hub dependency/);
      expect(screen).not.toMatch(/Hard ceilings are/);
    });
  }
});
