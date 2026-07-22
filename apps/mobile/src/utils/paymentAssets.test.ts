import { describe, expect, it } from "vitest";
import {
  PAYMENT_ASSETS,
  OFFICIAL_NODE_URL,
  computePortfolioUsd,
  hacdExplorerUrl,
  formatVisualGene,
  isValidHacdName,
  isOfficialNodeUrl,
  mapAssetPriceResponse,
  normalizeHacdName,
} from "@hacash/wallet-ui";

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
describe("shared wallet UI boundaries", () => {
  it("builds explorer links only for valid canonical HACD names", () => {
    expect(hacdExplorerUrl("vwmmmm")).toBe(
      "https://explorer.hacash.org/diamond/VWMMMM",
    );
    expect(hacdExplorerUrl("ABCD")).toBeNull();
  });

  it("accepts the documented 18 to 20 hex visual-gene shape", () => {
    for (const length of [18, 19, 20]) {
      expect(formatVisualGene("a".repeat(length))).not.toBeNull();
    }
    for (const length of [17, 21]) {
      expect(formatVisualGene("a".repeat(length))).toBeNull();
    }
  });

  it("recognizes only exact official node roots", () => {
    expect(OFFICIAL_NODE_URL).toBe("http://nodeapi.hacash.org");
    for (const url of [
      "http://nodeapi.hacash.org",
      "https://nodeapi.hacash.org",
      "http://nodeapi.org",
      "https://nodeapi.org/",
      "nodeapi.hacash.org",
      "nodeapi.org",
    ]) {
      expect(isOfficialNodeUrl(url)).toBe(true);
    }
    for (const url of [
      "",
      "   ",
      "http://user@nodeapi.hacash.org",
      "http://nodeapi.hacash.org:8081",
      "http://nodeapi.hacash.org.evil.example",
      "http://nodeapi.hacash.org/query/latest",
      "http://nodeapi.hacash.org?network=other",
    ]) {
      expect(isOfficialNodeUrl(url)).toBe(false);
    }
  });
  it("maps the exact typed USD quote contract", () => {
    expect(
      mapAssetPriceResponse({
        hac_usd: 0.25,
        hacd_usd: 50,
        btc_usd: 60_000,
        source: "coinpaprika",
        stale: false,
        observed_at_utc: "2026-07-18T00:00:00Z",
      }),
    ).toEqual({
      hacUsd: 0.25,
      hacdUsd: 50,
      btcUsd: 60_000,
      source: "coinpaprika",
      stale: false,
      observedAtUtc: "2026-07-18T00:00:00Z",
    });

    expect(() =>
      mapAssetPriceResponse({
        hac_usd: 0,
        hacd_usd: 50,
        btc_usd: 60_000,
        source: "coinpaprika",
        stale: false,
        observed_at_utc: "2026-07-18T00:00:00Z",
      }),
    ).toThrow("HAC USD price is missing or invalid");
  });

  it("rejects an invalid observed quote timestamp", () => {
    expect(() =>
      mapAssetPriceResponse({
        hac_usd: 0.25,
        hacd_usd: 50,
        btc_usd: 60_000,
        source: "coingecko",
        stale: true,
        observed_at_utc: "2026-02-30T00:00:00Z",
      }),
    ).toThrow("USD price timestamp is missing or invalid");
  });

  it("computes the portfolio once from HAC, HACD, and BTC-on-Hacash", () => {
    const prices = mapAssetPriceResponse({
      hac_usd: 0.25,
      hacd_usd: 50,
      btc_usd: 60_000,
      source: "coinpaprika",
      stale: false,
      observed_at_utc: "2026-07-18T00:00:00Z",
    });
    expect(
      computePortfolioUsd(
        {
          hac_mei: 10,
          hacd_count: 2,
          btc_wallet_satoshi: 100_000_000,
          btc_channel_satoshi: 50_000_000,
        },
        prices,
      ),
    ).toEqual({
      totalUsd: 90_102.5,
      hacUsd: 2.5,
      hacdUsd: 100,
      btcUsd: 90_000,
    });
  });
});
