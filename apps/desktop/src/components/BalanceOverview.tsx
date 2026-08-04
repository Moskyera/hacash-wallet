import {
  AssetMark,
  computePortfolioUsd,
  HACD_MARKET_REFERENCE_NOTICE,
  maskUsd,
  NativeAssetBalances,
  useAssetPrices,
} from "@hacash/wallet-ui";
import type { ReactNode } from "react";
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
            <div className="balance-primary">
              <span className="balance-primary-value">{maskBalance(assets?.hac_mei ?? null, hideBalances)}</span>
              <span className="balance-primary-unit">HAC</span>
            </div>
            <p className="balance-total-usd">{maskUsd(portfolio?.totalUsd, hideBalances)} {t("balance.totalUsd")}</p>
          </div>
        </section>
        <div className="balance-assets-grid">
          <AssetCard kind="hac" label="HAC" amount={maskBalance(assets?.hac_mei ?? null, hideBalances)} usd={maskUsd(portfolio?.hacUsd, hideBalances)} trend={hideBalances ? [] : trends.hac} />
          <AssetCard kind="hacd" label="HACD" amount={maskAssetCount(hacdCount, hideBalances)} hint={hacdHint} usd={maskUsd(portfolio?.hacdUsd, hideBalances)} trend={hideBalances ? [] : trends.hacd} />
          <AssetCard kind="hip20" label="HIP-20 assets" amount={hideBalances ? "••••" : `${nativeAssetCount}`} hint={hideBalances ? null : nativeAssetCount === 1 ? "1 native asset" : `${nativeAssetCount} native assets`} usd={nativeAssetCount > 0 ? "Native on Hacash" : "No assets detected"} trend={hideBalances ? [] : trends.hip20} />
          <AssetCard kind="btc" label="BTC on Hacash" amount={maskBtcFromSatoshi(btcTotalSat || null, hideBalances)} hint={btcChannelHint} usd={maskUsd(portfolio?.btcUsd, hideBalances)} trend={hideBalances ? [] : trends.btc} />
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

type AssetCardProps = {
  kind: "hac" | "hacd" | "btc" | "hip20";
  label: string;
  amount: string;
  hint?: string | null;
  usd: string;
  trend: number[];
};

function AssetCard({ kind, label, amount, hint, usd, trend }: AssetCardProps) {
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