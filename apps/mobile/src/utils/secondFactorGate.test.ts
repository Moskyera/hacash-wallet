import { describe, expect, it } from "vitest";
import { needsSecondFactor } from "./secondFactorGate";

describe("needsSecondFactor", () => {
  it("always requires 2FA for paranoid profile", () => {
    expect(needsSecondFactor(1, "paranoid")).toBe(true);
    expect(needsSecondFactor(0.01, "paranoid")).toBe(true);
  });

  it("requires 2FA for balanced profile at threshold", () => {
    expect(needsSecondFactor(100, "balanced")).toBe(true);
    expect(needsSecondFactor(99.9, "balanced")).toBe(false);
  });

  it("defaults to balanced behavior when profile missing", () => {
    expect(needsSecondFactor(100, null)).toBe(true);
    expect(needsSecondFactor(50, undefined)).toBe(false);
  });
});