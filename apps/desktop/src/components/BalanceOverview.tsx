import {
  AssetMark,
  computePortfolioUsd,
  HACD_MARKET_REFERENCE_NOTICE,
  maskUsd,
  NativeAssetBalances,
  useAssetPrices,
} from "@hacash/wallet-ui";
import { useMemo, type ReactNode } from "react";
import { api, type AssetSummary } from "../api";
import {
  trendDirection,
  trendPolyline,
  type AssetTrendHistory,
} from "../assetTrends";
import { useLocale } from "../locale";
import {
  formatBtcFromSatoshi,
  maskAssetCount,
  maskBalance,
  maskBtcFromSatoshi,
} from "../privacy";
import { WALLET_VERSION } from "../walletVersion";

type Props = {
  assets: AssetSummary | null;
  trends: AssetTrendHistory;
  hideBalances: boolean;
  topHint?: ReactNode;
};

export default function BalanceOverview({ assets, trends, hideBalances, topHint }: Props) {
  const { t } = useLocale();
  const { prices, status: priceStatus } = useAssetPrices(api.fetchAssetPrices);
  const portfolio = assets && prices ? computePortfolioUsd(assets, prices) : null;

  /**
   * Portfolio value across the balance readings this device has taken.
   *
   * Every point uses today's price, so the line moves when holdings move and
   * stays flat when they do not. It is not a price chart and cannot be: the
   * price feed carries a spot value with no history behind it. The aria-label
   * says exactly that, and the line is hidden until there are two readings to
   * join, rather than drawing a shape out of one.
   */
  const portfolioTrend = useMemo(() => {
    if (!prices || hideBalances) return [];
    const length = Math.min(trends.hac.length, trends.hacd.length, trends.btc.length);
    return Array.from({ length }, (_, index) =>
      (trends.hac[index] ?? 0) * prices.hacUsd +
      (trends.hacd[index] ?? 0) * prices.hacdUsd +
      ((trends.btc[index] ?? 0) / 100_000_000) * prices.btcUsd,
    );
  }, [prices, hideBalances, trends]);

  const hacdCount = assets?.hacd_count ?? null;
  const hacdHint =
    !hideBalances && assets && assets.hacd_count > 0 && assets.hacd_names.length > 0
      ? assets.hacd_names.slice(0, 2).join(", ") + (assets.hacd_count > 2 ? "…" : "")
      : null;

  const btcWalletSat = assets?.btc_wallet_satoshi ?? 0;
  const btcChannelSat = assets?.btc_channel_satoshi ?? 0;
  const btcTotalSat = btcWalletSat + btcChannelSat;
  const btcChannelHint =
    !hideBalances && btcChannelSat > 0
      ? `+ ${formatBtcFromSatoshi(btcChannelSat)} in Fast Pay`
      : null;
  const nativeAssetCount = assets?.native_assets.length ?? 0;

  return (
    <div className="balance-portfolio">
      <div className="balance-portfolio-layout">
        <section className="balance-total-card">
          <div className="balance-portfolio-header">
            <span className="label">Total portfolio</span>
            <span className="wallet-version">HPAY {WALLET_VERSION}</span>
          </div>
          {topHint}
          <div className="balance-portfolio-total">
            {/* The USD figure leads, as the design asks, but only while a price is
                actually available. It comes from an external source that can be
                missing or stale, and the balance is the number the wallet itself
                knows. When there is no price, the balance leads instead: "N/A"
                must never be the largest text on a wallet screen. */}
            {portfolio ? (
              <>
                <div className="balance-primary">
                  <span className="balance-primary-value">{maskUsd(portfolio.totalUsd, hideBalances)}</span>
                  <span className="balance-primary-unit">USD</span>
                </div>
                <p className="balance-total-usd">
                  &asymp; {maskBalance(assets?.hac_mei ?? null, hideBalances)} HAC
                </p>
                {portfolioTrend.length > 1 ? (
                  <svg
                    className={`balance-total-trend asset-trend asset-trend-${trendDirection(portfolioTrend)}`}
                    viewBox="0 0 120 40"
                    preserveAspectRatio="none"
                    role="img"
                    aria-label={`Portfolio value across the last ${portfolioTrend.length} balance readings on this device: ${trendDirection(portfolioTrend)}`}
                  >
                    <polyline key={trendPolyline(portfolioTrend, 120, 40)} points={trendPolyline(portfolioTrend, 120, 40)} pathLength="1" />
                  </svg>
                ) : null}
              </>
            ) : (
              <>
                <div className="balance-primary">
                  <span className="balance-primary-value">{maskBalance(assets?.hac_mei ?? null, hideBalances)}</span>
                  <span className="balance-primary-unit">HAC</span>
                </div>
                <p className="balance-total-usd">{t("prices.unavailable")}</p>
              </>
            )}
          </div>
        </section>
        <div className="balance-assets-grid">
          <AssetCard kind="hac" label="HAC" amount={maskBalance(assets?.hac_mei ?? null, hideBalances)} usd={maskUsd(portfolio?.hacUsd, hideBalances)} unitPrice={formatUnitPrice(prices?.hacUsd)} trend={hideBalances ? [] : trends.hac} />
          <AssetCard kind="hacd" label="HACD" amount={maskAssetCount(hacdCount, hideBalances)} hint={hacdHint} usd={maskUsd(portfolio?.hacdUsd, hideBalances)} unitPrice={formatUnitPrice(prices?.hacdUsd)} trend={hideBalances ? [] : trends.hacd} />
          <AssetCard kind="hip20" label="HIP-20 assets" amount={hideBalances ? "••••" : `${nativeAssetCount}`} hint={hideBalances ? null : nativeAssetCount === 1 ? "1 native asset" : `${nativeAssetCount} native assets`} usd={nativeAssetCount > 0 ? "Native on Hacash" : "No assets detected"} trend={hideBalances ? [] : trends.hip20} />
          <AssetCard kind="btc" label="BTC on Hacash" amount={maskBtcFromSatoshi(btcTotalSat || null, hideBalances)} hint={btcChannelHint} usd={maskUsd(portfolio?.btcUsd, hideBalances)} unitPrice={formatUnitPrice(prices?.btcUsd)} trend={hideBalances ? [] : trends.btc} />
        </div>
      </div>

      <NativeAssetBalances assets={assets?.native_assets ?? []} hidden={hideBalances} loadMetadata={api.queryNativeAssetMetadata} />

      {!hideBalances && portfolio && hacdCount != null && hacdCount > 0 ? (
        <p className="muted small-note balance-usd-note">{HACD_MARKET_REFERENCE_NOTICE}</p>
      ) : null}
      {!hideBalances && priceStatus === "unavailable" && (
        <p className="muted small-note balance-usd-note">{t("prices.unavailable")}</p>
      )}
      {!hideBalances && priceStatus === "stale" && (
        <p className="muted small-note balance-usd-note">{t("prices.stale")}</p>
      )}
    </div>
  );
}

/**
 * One unit of the asset in USD.
 *
 * Deliberately not masked by the privacy setting. Hiding balances hides what
 * this wallet holds; a public market price says nothing about the holder, so
 * blanking it would cost readability and buy no privacy.
 */
function formatUnitPrice(value: number | undefined): string | null {
  if (value == null || !Number.isFinite(value) || value <= 0) return null;
  const digits = value < 1 ? 4 : 2;
  return `$${value.toLocaleString("en-US", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })}`;
}

type AssetCardProps = {
  kind: "hac" | "hacd" | "btc" | "hip20";
  label: string;
  amount: string;
  hint?: string | null;
  usd: string;
  /**
   * Spot price of one unit. Shown without a change percentage on purpose:
   * the price feed carries a spot value only, so there is no 24-hour figure
   * to compare against and nothing to render an arrow from.
   */
  unitPrice?: string | null;
  trend: number[];
};

function AssetCard({ kind, label, amount, hint, usd, unitPrice, trend }: AssetCardProps) {
  const points = trendPolyline(trend);
  const direction = trendDirection(trend);

  return (
    <article className={`balance-asset-card balance-asset-card-${kind}`}>
      <header className="balance-asset-heading">
        <AssetMark kind={kind} size="md" />
        <span className="symbol">{label}</span>
      </header>
      <span className="amount">{amount}</span>
      {hint ? <span className="hint">{hint}</span> : null}
      <span className="usd">{usd}</span>
      {unitPrice ? <span className="balance-asset-unit-price">{unitPrice}</span> : null}
      <svg
        className={`asset-trend asset-trend-${direction}`}
        viewBox="0 0 120 30"
        preserveAspectRatio="none"
        role="img"
        aria-label={`${label} balance trend: ${direction}`}
      >
        <polyline key={points} points={points} pathLength="1" />
      </svg>
    </article>
  );
}