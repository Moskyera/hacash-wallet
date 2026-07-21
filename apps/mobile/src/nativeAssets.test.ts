import { describe, expect, it } from "vitest";
import {
  isCanonicalNativeAssetList,
  nativeAssetDisclosure,
} from "@hacash/wallet-ui";

describe("native asset read-only DTO", () => {
  it("preserves the full u64 range as decimal strings", () => {
    expect(
      isCanonicalNativeAssetList([
        { serial: "1", amount: "18446744073709551615" },
      ]),
    ).toBe(true);
  });

  it("rejects values outside u64 and non-canonical decimals", () => {
    expect(
      isCanonicalNativeAssetList([
        { serial: "1", amount: "18446744073709551616" },
      ]),
    ).toBe(false);
    expect(isCanonicalNativeAssetList([{ serial: "01", amount: "2" }])).toBe(false);
    expect(isCanonicalNativeAssetList([{ serial: "1", amount: "0" }])).toBe(false);
  });

  it("requires sorted unique serials and the consensus item cap", () => {
    expect(
      isCanonicalNativeAssetList([
        { serial: "2", amount: "1" },
        { serial: "1", amount: "1" },
      ]),
    ).toBe(false);
    expect(
      isCanonicalNativeAssetList([
        { serial: "7", amount: "1" },
        { serial: "7", amount: "2" },
      ]),
    ).toBe(false);
    expect(
      isCanonicalNativeAssetList(
        Array.from({ length: 21 }, (_, index) => ({ serial: String(index + 1), amount: "1" })),
      ),
    ).toBe(false);
  });

  it("does not retain count, serials or balances in hidden disclosure state", () => {
    const disclosure = nativeAssetDisclosure(
      [{ serial: "18446744073709551615", amount: "7654321" }],
      true,
    );
    expect(disclosure).toEqual({ status: "hidden" });
    expect(JSON.stringify(disclosure)).not.toContain("18446744073709551615");
    expect(JSON.stringify(disclosure)).not.toContain("7654321");
  });

  it("validates and returns balances only in visible disclosure state", () => {
    const assets = [{ serial: "7", amount: "12" }] as const;
    expect(nativeAssetDisclosure(assets, false)).toEqual({
      status: "visible",
      assets,
      valid: true,
    });
  });
});
