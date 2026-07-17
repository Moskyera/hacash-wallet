import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { AssetPrices } from "../utils/portfolioUsd";

const REFRESH_MS = 5 * 60 * 1000;

export function useAssetPrices() {
  const [prices, setPrices] = useState<AssetPrices | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api.fetchAssetPrices();
      setPrices({ hacUsd: data.hac_usd, btcUsd: data.btc_usd, fetchedAt: Date.now() });
      setError(null);
    } catch (e) {
      setError(String(e));
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

  return { prices, loading, error, refresh };
}
