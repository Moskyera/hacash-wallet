import { useCallback, useEffect, useRef, useState } from "react";

export type AssetPriceSource = "coinpaprika" | "coingecko";

export type AssetPriceResponse = {
  hac_usd: number;
  hacd_usd: number;
  btc_usd: number;
  source: AssetPriceSource;
  stale: boolean;
  observed_at_utc: string;
};

export type AssetPrices = {
  hacUsd: number;
  hacdUsd: number;
  btcUsd: number;
  source: AssetPriceSource;
  stale: boolean;
  observedAtUtc: string;
};

export type AssetPriceStatus = "loading" | "fresh" | "stale" | "unavailable";

export type PortfolioAssets = {
  hac_mei: number;
  hacd_count: number;
  btc_wallet_satoshi: number;
  btc_channel_satoshi: number;
};

export type PortfolioUsd = {
  totalUsd: number;
  hacUsd: number;
  hacdUsd: number;
  btcUsd: number;
};

export const ASSET_PRICE_REFRESH_MS = 5 * 60 * 1000;
export const ASSET_PRICE_FAILURE_RETRY_MS = 30 * 1000;
export const ASSET_PRICE_CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
export const HACD_MARKET_REFERENCE_NOTICE =
  "HACD market reference, not an individual diamond valuation.";
const ASSET_PRICE_CACHE_KEY = "hacash.wallet.asset-prices.v1";
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;


function positivePrice(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${label} USD price is missing or invalid`);
  }
  return value;
}

function requireObservedAtUtc(value: unknown): string {
  if (typeof value !== "string") throw new Error("USD price timestamp is missing or invalid");
  const match = RFC3339_RE.exec(value);
  if (!match) throw new Error("USD price timestamp is missing or invalid");

  const [, yearText, monthText, dayText, hourText, minuteText, secondText, zone] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(0, 0, 0, 0);
  const validCalendarDate =
    calendar.getUTCFullYear() === year &&
    calendar.getUTCMonth() === month - 1 &&
    calendar.getUTCDate() === day;
  const validTime = hour <= 23 && minute <= 59 && second <= 59;
  const validOffset =
    zone === "Z" || (Number(zone.slice(1, 3)) <= 23 && Number(zone.slice(4, 6)) <= 59);
  if (!validCalendarDate || !validTime || !validOffset || !Number.isFinite(Date.parse(value))) {
    throw new Error("USD price timestamp is missing or invalid");
  }
  return value;
}

export function mapAssetPriceResponse(
  response: AssetPriceResponse,
): AssetPrices {
  const source = response.source;
  if (source !== "coinpaprika" && source !== "coingecko") {
    throw new Error("USD price source is missing or invalid");
  }
  if (typeof response.stale !== "boolean") throw new Error("USD price freshness is invalid");
  return {
    hacUsd: positivePrice(response.hac_usd, "HAC"),
    hacdUsd: positivePrice(response.hacd_usd, "HACD"),
    btcUsd: positivePrice(response.btc_usd, "BTC"),
    source,
    stale: response.stale,
    observedAtUtc: requireObservedAtUtc(response.observed_at_utc),
  };
}

function hasUsableAge(observedAtUtc: string, nowMs: number): boolean {
  const observedMs = Date.parse(observedAtUtc);
  return (
    Number.isFinite(observedMs) &&
    observedMs <= nowMs + MAX_CLOCK_SKEW_MS &&
    nowMs - observedMs <= ASSET_PRICE_CACHE_MAX_AGE_MS
  );
}

/** Parse a previously verified informational quote. Cached prices never become fresh. */
export function parseCachedAssetPrices(raw: string | null, nowMs = Date.now()): AssetPrices | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as { version?: unknown; prices?: Partial<AssetPrices> };
    if (parsed.version !== 1 || !parsed.prices) return null;
    const prices = parsed.prices;
    const source = prices.source;
    if (source !== "coinpaprika" && source !== "coingecko") return null;
    const observedAtUtc = requireObservedAtUtc(prices.observedAtUtc);
    if (!hasUsableAge(observedAtUtc, nowMs)) return null;
    return {
      hacUsd: positivePrice(prices.hacUsd, "HAC"),
      hacdUsd: positivePrice(prices.hacdUsd, "HACD"),
      btcUsd: positivePrice(prices.btcUsd, "BTC"),
      source,
      stale: true,
      observedAtUtc,
    };
  } catch {
    return null;
  }
}

export function serializeCachedAssetPrices(prices: AssetPrices): string {
  return JSON.stringify({ version: 1, prices });
}

function readBrowserPriceCache(): AssetPrices | null {
  if (typeof window === "undefined") return null;
  try {
    return parseCachedAssetPrices(window.localStorage.getItem(ASSET_PRICE_CACHE_KEY));
  } catch {
    return null;
  }
}

function writeBrowserPriceCache(prices: AssetPrices): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(ASSET_PRICE_CACHE_KEY, serializeCachedAssetPrices(prices));
  } catch {
    // Storage can be disabled. Live native prices remain available.
  }
}

export function computePortfolioUsd(
  assets: PortfolioAssets,
  prices: AssetPrices,
): PortfolioUsd {
  const hacUsd = assets.hac_mei * prices.hacUsd;
  const hacdUsd = assets.hacd_count * prices.hacdUsd;
  const btc = (assets.btc_wallet_satoshi + assets.btc_channel_satoshi) / 100_000_000;
  const btcUsd = btc * prices.btcUsd;
  return {
    totalUsd: hacUsd + hacdUsd + btcUsd,
    hacUsd,
    hacdUsd,
    btcUsd,
  };
}

export function formatUsd(value: number): string {
  if (!Number.isFinite(value)) return "N/A";
  if (value >= 1_000_000) {
    return `$${(value / 1_000_000).toLocaleString("en-US", { maximumFractionDigits: 2 })}M`;
  }
  if (value >= 10_000) {
    return `$${value.toLocaleString("en-US", { maximumFractionDigits: 0 })}`;
  }
  if (value >= 1) {
    return `$${value.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
  return `$${value.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 4 })}`;
}

export function maskUsd(value: number | null | undefined, hide: boolean): string {
  if (hide) return "\u2022".repeat(4);
  if (value == null) return "N/A";
  return formatUsd(value);
}

export function useAssetPrices(
  fetchPrices: () => Promise<AssetPriceResponse>,
  refreshMs = ASSET_PRICE_REFRESH_MS,
  failureRetryMs = ASSET_PRICE_FAILURE_RETRY_MS,
) {
  const [prices, setPrices] = useState<AssetPrices | null>(readBrowserPriceCache);
  const pricesRef = useRef<AssetPrices | null>(prices);
  const [status, setStatus] = useState<AssetPriceStatus>(prices ? "stale" : "loading");
  const [loading, setLoading] = useState(!prices);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef<Promise<boolean> | null>(null);

  const refreshWithStatus = useCallback((): Promise<boolean> => {
    if (inFlight.current) return inFlight.current;
    const request = (async () => {
      try {
        const next = mapAssetPriceResponse(await fetchPrices());
        pricesRef.current = next;
        setPrices(next);
        setStatus(next.stale ? "stale" : "fresh");
        writeBrowserPriceCache(next);
        setError(null);
        return true;
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
        const cached = pricesRef.current;
        if (cached && hasUsableAge(cached.observedAtUtc, Date.now())) {
          const stale = { ...cached, stale: true };
          pricesRef.current = stale;
          setPrices(stale);
          setStatus("stale");
        } else {
          pricesRef.current = null;
          setPrices(null);
          setStatus("unavailable");
        }
        return false;
      } finally {
        setLoading(false);
      }
    })().finally(() => {
      if (inFlight.current === request) inFlight.current = null;
    });
    inFlight.current = request;
    return request;
  }, [fetchPrices]);

  const refresh = useCallback(async (): Promise<void> => {
    await refreshWithStatus();
  }, [refreshWithStatus]);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      const succeeded = await refreshWithStatus();
      if (!cancelled) {
        timer = window.setTimeout(poll, succeeded ? refreshMs : failureRetryMs);
      }
    };
    void poll();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [failureRetryMs, refreshMs, refreshWithStatus]);

  return { prices, status, loading, error, refresh };
}
