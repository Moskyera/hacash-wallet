import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (path: string) => readFileSync(join(HERE, path), "utf8");

describe("mobile bounded mainnet Fast Pay consent", () => {
  it("is explicit, persisted and required before channel funding", () => {
    const screen = read("screens/FastPayChannelScreen.tsx");
    const api = read("api.ts");

    expect(api).toContain("trusted_mainnet_fast_pay_pilot: boolean");
    expect(screen).toContain("Bounded mainnet pilot");
    expect(screen).toContain("not a trustless L1 exit");
    expect(screen).toContain("1 HAC per payment");
    expect(screen).toContain("10 HAC per channel");
    expect(screen).toContain("100 HAC");
    expect(screen).toContain("api.updateSettings");
    expect(screen).toContain("!settings.trusted_mainnet_fast_pay_pilot");
    expect(screen).toContain("Channel recovery remains available");
  });
});
