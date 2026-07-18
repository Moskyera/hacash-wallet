import { describe, expect, it } from "vitest";

import {
  canOpenLegacyFund,
  canUseQuantumLabTransactions,
  type4Balance,
  type Type4Probe,
} from "@hacash/wallet-ui";

describe("Type 4 funding probe", () => {
  it.each<Type4Probe>([
    { status: "idle" },
    { status: "loading" },
    { status: "failed", kind: "unsupported", message: "unsupported" },
    { status: "failed", kind: "other", message: "offline" },
  ])("blocks legacy funding while probe is $status", (probe) => {
    expect(canOpenLegacyFund(probe)).toBe(false);
    expect(type4Balance(probe)).toBeNull();
  });

  it("allows funding only after a verified balance response", () => {
    const probe: Type4Probe = { status: "ok", balance: 12.5 };

    expect(canOpenLegacyFund(probe)).toBe(true);
    expect(type4Balance(probe)).toBe(12.5);
  });
});

  it("enables Quantum Lab transactions only in explicit testnet mode", () => {
    expect(canUseQuantumLabTransactions("testnet")).toBe(true);
    expect(canUseQuantumLabTransactions("mainnet")).toBe(false);
    expect(canUseQuantumLabTransactions("custom")).toBe(false);
    expect(canUseQuantumLabTransactions(null)).toBe(false);
    expect(canUseQuantumLabTransactions(undefined)).toBe(false);
  });
