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
  hideBalances: boolean;
  topHint?: ReactNode;
  actions?: ReactNode;
};

export default function BalanceOverview({ assets, hideBalances, topHint, actions }: Props) {
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
            <span className="label">Total balance</span>
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
        {actions ? <div className="mobile-primary-actions-slot">{actions}</div> : null}
        <div className="balance-assets-grid">
          <MobileAsset kind="hac" label="HAC" amount={maskBalance(assets?.hac_mei ?? null, hideBalances)} usd={maskUsd(portfolio?.hacUsd, hideBalances)} />
          <MobileAsset kind="hacd" label="HACD" amount={maskAssetCount(hacdCount, hideBalances)} hint={hacdHint} usd={maskUsd(portfolio?.hacdUsd, hideBalances)} />
          <MobileAsset kind="hip20" label="HIP-20" amount={hideBalances ? "••••" : String(nativeAssetCount)} hint={hideBalances ? null : `${nativeAssetCount} native assets`} usd="Native on Hacash" />
          <MobileAsset kind="btc" label="BTC on Hacash" amount={maskBtcFromSatoshi(btcTotalSat || null, hideBalances)} hint={btcChannelHint} usd={maskUsd(portfolio?.btcUsd, hideBalances)} />
        </div>
      </div>
      <NativeAssetBalances assets={assets?.native_assets ?? []} hidden={hideBalances} loadMetadata={api.queryNativeAssetMetadata} />
      {!hideBalances && portfolio && hacdCount != null && hacdCount > 0 ? <p className="muted small balance-usd-note">{HACD_MARKET_REFERENCE_NOTICE}</p> : null}
      {!hideBalances && priceStatus === "unavailable" ? <p className="muted small balance-usd-note">{t("prices.unavailable")}</p> : null}
      {!hideBalances && priceStatus === "stale" ? <p className="muted small balance-usd-note">{t("prices.stale")}</p> : null}
    </div>
  );
}

function MobileAsset({ kind, label, amount, hint, usd }: { kind: "hac" | "hacd" | "btc" | "hip20"; label: string; amount: string; hint?: string | null; usd: string }) {
  return (
    <article className={`balance-asset-card balance-asset-card-${kind}`}>
      <header className="balance-asset-heading"><AssetMark kind={kind} size="sm" /><span className="symbol">{label}</span></header>
      <span className="amount">{amount}</span>
      {hint ? <span className="hint">{hint}</span> : null}
      <span className="usd">{usd}</span>
    </article>
  );
}