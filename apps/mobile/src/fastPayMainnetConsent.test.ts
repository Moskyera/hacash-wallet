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
  it("names how the money is actually lost", () => {
    // "Fast Pay depends on the selected Hub and is not a trustless L1 exit" is
    // true and tells a person nothing. The loss is specific: an old receipt
    // put on chain while the owner is offline, a challenge window that closes
    // with nobody answering for them, and the older, worse split settles.
    expect(FAST_PAY_MAINNET_CONSENT).toMatch(/old receipt on chain while I am offline/);
    expect(FAST_PAY_MAINNET_CONSENT).toMatch(/lose part or all of what is in this channel/);
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
