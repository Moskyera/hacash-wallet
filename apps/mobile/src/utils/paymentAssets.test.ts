import { describe, expect, it } from "vitest";
import {
  PAYMENT_ASSETS,
  isValidHacdName,
  normalizeHacdName,
} from "./paymentAssets";

describe("payment asset identity", () => {
  it("labels BTC as an asset on Hacash", () => {
    expect(PAYMENT_ASSETS.find((asset) => asset.id === "BTC")?.label).toBe("On Hacash");
  });

  it("accepts only the official HACD alphabet", () => {
    expect(normalizeHacdName("vwmmmm")).toBe("VWMMMM");
    expect(isValidHacdName("VWMMMM")).toBe(true);
    expect(isValidHacdName("ABCDEF")).toBe(false);
    expect(normalizeHacdName("ABCD-WTYU")).toBe("ABWTYU");
  });
});