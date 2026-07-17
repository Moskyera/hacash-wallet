import type { AssetSummary } from "../api";

/** Conservative HAC floor per diamond for USD estimate (launchpad varies). */
export const HACD_FLOOR_HAC = 1;

export type AssetPrices = {
  hacUsd: number;
  btcUsd: number;
  fetchedAt: number;
};

export type PortfolioUsd = {
  totalUsd: number;
  hacUsd: number;
  hacdUsd: number;
  btcUsd: number;
};

export function computePortfolioUsd(assets: AssetSummary, prices: AssetPrices): PortfolioUsd {
  const hacUsd = assets.hac_mei * prices.hacUsd;
  const hacdUsd = assets.hacd_count * HACD_FLOOR_HAC * prices.hacUsd;
  const btcBtc = (assets.btc_wallet_satoshi + assets.btc_channel_satoshi) / 100_000_000;
  const btcUsd = btcBtc * prices.btcUsd;
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
  if (hide) return "••••";
  if (value == null) return "N/A";
  return formatUsd(value);
}