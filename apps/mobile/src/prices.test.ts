import {
  ASSET_PRICE_CACHE_MAX_AGE_MS,
  HACD_MARKET_REFERENCE_NOTICE,
  mapAssetPriceResponse,
  parseCachedAssetPrices,
  serializeCachedAssetPrices,
} from "@hacash/wallet-ui";
import { describe, expect, it } from "vitest";

const OBSERVED = "2026-07-18T10:00:00Z";
const NOW = Date.parse("2026-07-18T10:01:00Z");

function quote() {
  return mapAssetPriceResponse({
    hac_usd: 0.28,
    hacd_usd: 10.03,
    btc_usd: 63_900,
    source: "coinpaprika",
    stale: false,
    observed_at_utc: OBSERVED,
  });
}

describe("asset price cache", () => {
  it("labels HACD USD as a market reference rather than an individual valuation", () => {
    expect(HACD_MARKET_REFERENCE_NOTICE).toBe(
      "HACD market reference, not an individual diamond valuation.",
    );
  });

  it("restores a verified quote only as stale informational data", () => {
    const restored = parseCachedAssetPrices(serializeCachedAssetPrices(quote()), NOW);
    expect(restored).toEqual({ ...quote(), stale: true });
  });

  it("rejects expired, future, malformed and non-positive cached prices", () => {
    const valid = JSON.parse(serializeCachedAssetPrices(quote()));
    expect(
      parseCachedAssetPrices(
        JSON.stringify(valid),
        Date.parse(OBSERVED) + ASSET_PRICE_CACHE_MAX_AGE_MS + 1,
      ),
    ).toBeNull();
    expect(parseCachedAssetPrices(JSON.stringify(valid), Date.parse(OBSERVED) - 5 * 60 * 1000 - 1)).toBeNull();
    expect(parseCachedAssetPrices("not json", NOW)).toBeNull();
    valid.prices.hacUsd = 0;
    expect(parseCachedAssetPrices(JSON.stringify(valid), NOW)).toBeNull();
  });
});
