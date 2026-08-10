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
            {/* The USD figure leads while a price exists, and the balance leads
                when none does. The price comes from an external source that can
                be missing or stale; the balance is what the wallet itself knows,
                and "N/A" must never be the largest text on a wallet screen. */}
            {portfolio ? (
              <>
                <div className="balance-primary">
                  <span className="balance-primary-value">{maskUsd(portfolio.totalUsd, hideBalances)}</span>
                  <span className="balance-primary-unit">USD</span>
                </div>
                <p className="balance-total-usd">
                  &asymp; {maskBalance(assets?.hac_mei ?? null, hideBalances)} HAC
                </p>
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
        {actions ? <div className="mobile-primary-actions-slot">{actions}</div> : null}
        <div className="balance-assets-grid">
          <MobileAsset kind="hac" label="HAC" amount={maskBalance(assets?.hac_mei ?? null, hideBalances)} usd={maskUsd(portfolio?.hacUsd, hideBalances)} unitPrice={formatUnitPrice(prices?.hacUsd)} />
          <MobileAsset kind="hacd" label="HACD" amount={maskAssetCount(hacdCount, hideBalances)} hint={hacdHint} usd={maskUsd(portfolio?.hacdUsd, hideBalances)} unitPrice={formatUnitPrice(prices?.hacdUsd)} />
          <MobileAsset kind="hip20" label="HIP-20" amount={hideBalances ? "••••" : String(nativeAssetCount)} hint={hideBalances ? null : `${nativeAssetCount} native assets`} usd="Native on Hacash" />
          <MobileAsset kind="btc" label="BTC on Hacash" amount={maskBtcFromSatoshi(btcTotalSat || null, hideBalances)} hint={btcChannelHint} usd={maskUsd(portfolio?.btcUsd, hideBalances)} unitPrice={formatUnitPrice(prices?.btcUsd)} />
        </div>
      </div>
      <NativeAssetBalances assets={assets?.native_assets ?? []} hidden={hideBalances} loadMetadata={api.queryNativeAssetMetadata} />
      {!hideBalances && portfolio && hacdCount != null && hacdCount > 0 ? <p className="muted small balance-usd-note">{HACD_MARKET_REFERENCE_NOTICE}</p> : null}
      {!hideBalances && priceStatus === "unavailable" ? <p className="muted small balance-usd-note">{t("prices.unavailable")}</p> : null}
      {!hideBalances && priceStatus === "stale" ? <p className="muted small balance-usd-note">{t("prices.stale")}</p> : null}
    </div>
  );
}

/**
 * One unit of the asset in USD.
 *
 * Not masked by the privacy setting: hiding balances hides what this wallet
 * holds, and a public market price says nothing about the holder. Shown with no
 * change percentage, because the price feed carries a spot value with no history
 * behind it and there is nothing to draw an arrow from.
 */
function formatUnitPrice(value: number | undefined): string | null {
  if (value == null || !Number.isFinite(value) || value <= 0) return null;
  const digits = value < 1 ? 4 : 2;
  return `$${value.toLocaleString("en-US", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })}`;
}

function MobileAsset({ kind, label, amount, hint, usd, unitPrice }: { kind: "hac" | "hacd" | "btc" | "hip20"; label: string; amount: string; hint?: string | null; usd: string; unitPrice?: string | null }) {
  return (
    <article className={`balance-asset-card balance-asset-card-${kind}`}>
      <header className="balance-asset-heading"><AssetMark kind={kind} size="sm" /><span className="symbol">{label}</span></header>
      <span className="amount">{amount}</span>
      {hint ? <span className="hint">{hint}</span> : null}
      <span className="usd">{usd}</span>
      {unitPrice ? <span className="balance-asset-unit-price">{unitPrice}</span> : null}
    </article>
  );
}