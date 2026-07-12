import type { ReactNode } from "react";
import type { AssetSummary } from "../api";
import { useAssetPrices } from "../hooks/useAssetPrices";
import {
  formatBtcFromSatoshi,
  maskAssetCount,
  maskBalance,
  maskBtcFromSatoshi,
} from "../privacy";
import { computePortfolioUsd, maskUsd } from "../utils/portfolioUsd";
import { WALLET_VERSION } from "../walletVersion";

type Props = {
  assets: AssetSummary | null;
  hideBalances: boolean;
  topHint?: ReactNode;
};

export default function BalanceOverview({ assets, hideBalances, topHint }: Props) {
  const { prices } = useAssetPrices();
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

  return (
    <div className="balance-portfolio">
      <div className="balance-portfolio-header">
        <span className="label">Available balance</span>
        <span className="wallet-version">{WALLET_VERSION}</span>
      </div>

      {topHint}

      <div className="balance-portfolio-total">
        <div className="balance-primary">
          <span className="balance-primary-value">{maskBalance(assets?.hac_mei ?? null, hideBalances)}</span>
          <span className="balance-primary-unit">HAC</span>
        </div>
        <p className="balance-total-usd">{maskUsd(portfolio?.totalUsd, hideBalances)} total</p>
      </div>

      <div className="balance-assets-grid">
        <div className="balance-asset-card balance-asset-card-hac">
          <span className="symbol">HAC</span>
          <span className="amount">{maskBalance(assets?.hac_mei ?? null, hideBalances)}</span>
          <span className="usd">{maskUsd(portfolio?.hacUsd, hideBalances)}</span>
        </div>

        <div className="balance-asset-card balance-asset-card-hacd">
          <span className="symbol">HACD</span>
          <span className="amount">{maskAssetCount(hacdCount, hideBalances)}</span>
          {hacdHint ? <span className="hint">{hacdHint}</span> : null}
          <span className="usd">{maskUsd(portfolio?.hacdUsd, hideBalances)}</span>
        </div>

        <div className="balance-asset-card balance-asset-card-btc">
          <span className="symbol">BTC</span>
          <span className="amount">{maskBtcFromSatoshi(btcTotalSat || null, hideBalances)}</span>
          {btcChannelHint ? <span className="hint">{btcChannelHint}</span> : null}
          <span className="usd">{maskUsd(portfolio?.btcUsd, hideBalances)}</span>
        </div>
      </div>

      {!hideBalances && (assets?.hacd_count ?? 0) > 0 && (
        <p className="muted small-note balance-usd-note">
          HACD USD uses a 1 HAC floor estimate per diamond. Live market prices vary.
        </p>
      )}
    </div>
  );
}