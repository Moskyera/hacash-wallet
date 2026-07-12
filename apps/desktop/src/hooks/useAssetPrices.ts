import { useCallback, useEffect, useState } from "react";
import type { AssetPrices } from "../utils/portfolioUsd";

const COINGECKO_URL =
  "https://api.coingecko.com/api/v3/simple/price?ids=hacash,bitcoin&vs_currencies=usd";
const REFRESH_MS = 5 * 60 * 1000;

export function useAssetPrices() {
  const [prices, setPrices] = useState<AssetPrices | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch(COINGECKO_URL);
      if (!res.ok) throw new Error(`price fetch ${res.status}`);
      const data = (await res.json()) as {
        hacash?: { usd?: number };
        bitcoin?: { usd?: number };
      };
      const hacUsd = data.hacash?.usd;
      const btcUsd = data.bitcoin?.usd;
      if (hacUsd == null || btcUsd == null) throw new Error("missing price fields");
      setPrices({ hacUsd, btcUsd, fetchedAt: Date.now() });
    } catch {
      setPrices((prev) => prev);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), REFRESH_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  return { prices, loading, refresh };
}