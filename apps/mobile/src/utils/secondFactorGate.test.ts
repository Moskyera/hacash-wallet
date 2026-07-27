import { describe, expect, it } from "vitest";
import { needsSecondFactor } from "./secondFactorGate";

describe("needsSecondFactor", () => {
  it("always requires 2FA for paranoid profile", () => {
    expect(needsSecondFactor(1, "paranoid")).toBe(true);
    expect(needsSecondFactor(0.01, "paranoid")).toBe(true);
  });

  it("requires 2FA for balanced profile at threshold", () => {
    expect(needsSecondFactor(100, "balanced")).toBe(true);
    expect(needsSecondFactor(99, "balanced")).toBe(false);
  });

  // The core rounds the policed amount up before comparing (policy_amount_mei_ceil),
  // so anything above 99 needs a factor. Claiming otherwise routes the payment to the
  // Fast Pay rail, which cannot authorize it, and the core then refuses at the moment
  // of paying instead of the interface offering Force L1 up front.
  it("rounds up like the core does", () => {
    expect(needsSecondFactor(99.001, "balanced")).toBe(true);
    expect(needsSecondFactor(99.9, "balanced")).toBe(true);
    expect(needsSecondFactor(99.0, "balanced")).toBe(false);
  });

  // A hardware gate applies to every payment, and Cold Vault needs a fresh factor for
  // every signature. Neither can be expressed as an amount threshold.
  it("requires 2FA for every amount under a hardware gate or Cold Vault", () => {
    expect(needsSecondFactor(0.01, "balanced", "webauthn_gate")).toBe(true);
    expect(needsSecondFactor(0.01, "balanced", "airgap_only")).toBe(true);
    expect(needsSecondFactor(1, "balanced", "software")).toBe(false);
  });

  it("defaults to balanced behavior when profile missing", () => {
    expect(needsSecondFactor(100, null)).toBe(true);
    expect(needsSecondFactor(50, undefined)).toBe(false);
  });
  // The core reports the amount it enforces, already combining the authenticated profile
  // with the user's choice. Deciding from the constant instead would route a payment to
  // Fast Pay that the core then refuses.
  it("uses the threshold the core reports, not the built-in constant", () => {
    expect(needsSecondFactor(10, "balanced", "software", 5)).toBe(true);
    expect(needsSecondFactor(4, "balanced", "software", 5)).toBe(false);
    expect(needsSecondFactor(4.5, "balanced", "software", 5)).toBe(true);
    // A reported value cannot loosen what the profile already demands.
    expect(needsSecondFactor(1, "paranoid", "software", 50)).toBe(true);
    expect(needsSecondFactor(1, "balanced", "airgap_only", 50)).toBe(true);
    // Missing or nonsensical values fall back to the default rather than passing 0 into
    // a comparison, which would demand a factor for nothing at all.
    expect(needsSecondFactor(50, "balanced", "software", null)).toBe(false);
    expect(needsSecondFactor(50, "balanced", "software", 0)).toBe(false);
    expect(needsSecondFactor(100, "balanced", "software", undefined)).toBe(true);
  });
});
