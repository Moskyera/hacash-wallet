import type { AssetSummary } from "./api";

export type AssetTrendKey = "hac" | "hacd" | "hip20" | "btc";
export type AssetTrendHistory = Record<AssetTrendKey, number[]>;
export type AssetTrendDirection = "up" | "down" | "flat";

const TREND_KEYS: AssetTrendKey[] = ["hac", "hacd", "hip20", "btc"];

export function emptyAssetTrends(): AssetTrendHistory {
  return {
    hac: [],
    hacd: [],
    hip20: [],
    btc: [],
  };
}

export function assetSnapshot(summary: AssetSummary): Record<AssetTrendKey, number> {
  return {
    hac: finiteNonNegative(summary.hac_mei),
    hacd: finiteNonNegative(summary.hacd_count),
    hip20: finiteNonNegative(summary.native_assets.length),
    btc: finiteNonNegative(
      summary.btc_wallet_satoshi + summary.btc_channel_satoshi,
    ),
  };
}

export function appendAssetSnapshot(
  history: AssetTrendHistory,
  summary: AssetSummary,
  limit = 12,
): AssetTrendHistory {
  const snapshot = assetSnapshot(summary);
  const safeLimit = Math.max(2, Math.floor(limit));

  return TREND_KEYS.reduce<AssetTrendHistory>((next, key) => {
    next[key] = [...history[key], snapshot[key]].slice(-safeLimit);
    return next;
  }, emptyAssetTrends());
}

export function trendDirection(values: number[]): AssetTrendDirection {
  if (values.length < 2) return "flat";
  const first = finiteNonNegative(values[0]);
  const last = finiteNonNegative(values[values.length - 1] ?? first);
  if (last > first) return "up";
  if (last < first) return "down";
  return "flat";
}

export function trendPolyline(
  values: number[],
  width = 120,
  height = 30,
  padding = 4,
): string {
  const safeWidth = Math.max(2, width);
  const safeHeight = Math.max(2, height);
  const safePadding = Math.max(
    0,
    Math.min(padding, safeWidth / 2 - 1, safeHeight / 2 - 1),
  );
  const samples = values.map(finiteNonNegative);
  const left = safePadding;
  const right = safeWidth - safePadding;
  const top = safePadding;
  const bottom = safeHeight - safePadding;
  const middle = (top + bottom) / 2;

  if (samples.length < 2) {
    return `${formatPoint(left)},${formatPoint(middle)} ${formatPoint(right)},${formatPoint(middle)}`;
  }

  const min = Math.min(...samples);
  const max = Math.max(...samples);
  const range = max - min;
  const xStep = (right - left) / (samples.length - 1);

  return samples
    .map((value, index) => {
      const x = left + xStep * index;
      const y = range === 0
        ? middle
        : bottom - ((value - min) / range) * (bottom - top);
      return `${formatPoint(x)},${formatPoint(y)}`;
    })
    .join(" ");
}

function finiteNonNegative(value: number): number {
  return Number.isFinite(value) && value > 0 ? value : 0;
}

function formatPoint(value: number): string {
  return Number(value.toFixed(2)).toString();
}
