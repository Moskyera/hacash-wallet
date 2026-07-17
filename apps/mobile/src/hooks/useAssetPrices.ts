import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { AssetPrices } from "../utils/portfolioUsd";

const REFRESH_MS = 5 * 60 * 1000;

export function useAssetPrices() {
  const [prices, setPrices] = useState<AssetPrices | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      // Rust HTTP works on GrapheneOS even when the WebView blocks third-party fetch.
      const data = await api.fetchAssetPrices();
      setPrices({ hacUsd: data.hac_usd, btcUsd: data.btc_usd, fetchedAt: Date.now() });
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
