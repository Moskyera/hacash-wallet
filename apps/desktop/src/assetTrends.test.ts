import { describe, expect, it } from "vitest";
import type { AssetSummary } from "./api";
import {
  appendAssetSnapshot,
  assetSnapshot,
  emptyAssetTrends,
  trendDirection,
  trendPolyline,
} from "./assetTrends";

function summary(overrides: Partial<AssetSummary> = {}): AssetSummary {
  return {
    hac_mei: 0,
    hacd_count: 0,
    hacd_names: [],
    btc_wallet_satoshi: 0,
    btc_channel_satoshi: 0,
    native_assets: [],
    ...overrides,
  };
}

describe("desktop asset trends", () => {
  it("derives every indicator from the real wallet asset fields", () => {
    expect(
      assetSnapshot(
        summary({
          hac_mei: 25,
          hacd_count: 3,
          btc_wallet_satoshi: 40,
          btc_channel_satoshi: 2,
          native_assets: [
            { serial: "1", amount: "10" },
            { serial: "2", amount: "20" },
          ],
        }),
      ),
    ).toEqual({ hac: 25, hacd: 3, hip20: 2, btc: 42 });
  });

  it("keeps a bounded refresh history for each asset", () => {
    let history = emptyAssetTrends();
    for (let value = 1; value <= 5; value += 1) {
      history = appendAssetSnapshot(history, summary({ hac_mei: value }), 3);
    }
    expect(history.hac).toEqual([3, 4, 5]);
    expect(history.hacd).toHaveLength(3);
  });

  it("reports rising, falling and unchanged balances", () => {
    expect(trendDirection([1, 2, 3])).toBe("up");
    expect(trendDirection([3, 2, 1])).toBe("down");
    expect(trendDirection([2, 2, 2])).toBe("flat");
    expect(trendDirection([2])).toBe("flat");
  });

  it("draws increases upward and decreases downward", () => {
    expect(trendPolyline([1, 2])).toBe("4,26 116,4");
    expect(trendPolyline([2, 1])).toBe("4,4 116,26");
    expect(trendPolyline([])).toBe("4,15 116,15");
  });

  it("sanitizes invalid samples instead of emitting invalid SVG", () => {
    const points = trendPolyline([Number.NaN, Number.POSITIVE_INFINITY, -1]);
    expect(points).toBe("4,15 60,15 116,15");
    expect(points).not.toMatch(/NaN|Infinity/);
  });
});
