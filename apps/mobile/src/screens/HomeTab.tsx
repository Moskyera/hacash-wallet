import type { AssetSummary, FastPayStatus, TxRecord } from "../api";
import HacdLaunchpadIcon from "../components/HacdLaunchpadIcon";
import { fastPayStatusLine, fastPayStatusTitle } from "../fastPayUi";
import { formatBtcFromSatoshi, maskAssetCount, maskBalance, maskBtcFromSatoshi } from "../privacy";

type Props = {
  assets: AssetSummary | null;
  hideBalances: boolean;
  refreshing: boolean;
  fastPay: FastPayStatus | null;
  watchOnly: boolean;
  busy: boolean;
  history: TxRecord[];
  onPullStart: (e: React.TouchEvent) => void;
  onPullMove: (e: React.TouchEvent) => void;
  onPullEnd: () => void;
  onEnableFastPay: () => void;
  onScanPay: () => void;
  onReceive: () => void;
  onContacts: () => void;
  onHistory: () => void;
  onQuantum: () => void;
  onLaunchpad: () => void;
};

export default function HomeTab({
  assets,
  hideBalances,
  refreshing,
  fastPay,
  watchOnly,
  busy,
  history,
  onPullStart,
  onPullMove,
  onPullEnd,
  onEnableFastPay,
  onScanPay,
  onReceive,
  onContacts,
  onHistory,
  onQuantum,
  onLaunchpad,
}: Props) {
  const hacdCount = assets?.hacd_count ?? null;
  const hacdHint =
    !hideBalances && assets && assets.hacd_count > 0 && assets.hacd_names.length > 0
      ? assets.hacd_names.slice(0, 3).join(", ") + (assets.hacd_count > 3 ? "…" : "")
      : null;
  const btcChannelSatoshi = assets?.btc_channel_satoshi ?? 0;
  const btcHint =
    !hideBalances && btcChannelSatoshi > 0
      ? `+ ${formatBtcFromSatoshi(btcChannelSatoshi)} BTC in Fast Pay`
      : null;

  return (
    <>
      <div
        className={`balance-hero ${refreshing ? "pulling" : ""}`}
        onTouchStart={onPullStart}
        onTouchMove={onPullMove}
        onTouchEnd={onPullEnd}
      >
        <p className="muted">{refreshing ? "Refreshing…" : "Pull down to refresh"}</p>
        <div className="amount">{maskBalance(assets?.hac_mei ?? null, hideBalances)}</div>
        <div className="unit">HAC</div>
        <div className="balance-assets">
          <div className="balance-asset">
            <span className="label">HACD</span>
            <span className="value">{maskAssetCount(hacdCount, hideBalances)}</span>
            {hacdHint && <span className="hint">{hacdHint}</span>}
          </div>
          <div className="balance-asset">
            <span className="label">BTC</span>
            <span className="value">{maskBtcFromSatoshi(assets?.btc_wallet_satoshi ?? null, hideBalances)}</span>
            {btcHint ? <span className="hint">{btcHint}</span> : <span className="hint">Wallet balance</span>}
          </div>
        </div>
      </div>

      {fastPay && fastPay.state !== "ready" && fastPay.can_enable && !watchOnly && (
        <div className="fp-banner">
          <div>
            <strong>{fastPayStatusTitle(fastPay.state)}</strong>
            <p className="muted">
              {fastPayStatusLine(fastPay.state, fastPay.default_deposit_mei ?? 10)}
            </p>
          </div>
          <button type="button" className="primary small" disabled={busy} onClick={() => void onEnableFastPay()}>
            Enable
          </button>
        </div>
      )}

      {fastPay?.state === "ready" && (
        <div className="fp-banner on">
          <div>
            <span className="badge badge-ok">Fast Pay on</span>
            <p className="muted">
              {fastPayStatusLine(fastPay.state, fastPay.default_deposit_mei ?? 10)}
            </p>
          </div>
        </div>
      )}

      {fastPay && fastPay.state !== "ready" && !fastPay.can_enable && (
        <div className="fp-banner">
          <div>
            <strong>{fastPayStatusTitle(fastPay.state)}</strong>
            <p className="muted">
              {fastPayStatusLine(fastPay.state, fastPay.default_deposit_mei ?? 10)}
            </p>
          </div>
        </div>
      )}

      {!watchOnly && (
        <div className="quick-actions">
          <button type="button" className="quick-action primary-action" onClick={onScanPay}>
            <span className="icon">📷</span>
            Scan & Pay
          </button>
          <button type="button" className="quick-action" onClick={onReceive}>
            <span className="icon">↗</span>
            Receive
          </button>
          <button type="button" className="quick-action" onClick={onContacts}>
            <span className="icon">👤</span>
            Contacts
          </button>
          <button type="button" className="quick-action" onClick={onHistory}>
            <span className="icon">📋</span>
            History
          </button>
          <button type="button" className="quick-action" onClick={onQuantum}>
            <span className="icon">◇</span>
            Quantum
          </button>
          <button type="button" className="quick-action" onClick={onLaunchpad}>
            <span className="icon" aria-hidden>
              <HacdLaunchpadIcon />
            </span>
            Launchpad
          </button>
        </div>
      )}

      {history.length > 0 && (
        <div className="card card-flat">
          <h2>Recent</h2>
          {history.slice(0, 3).map((row) => (
            <div key={row.tx_hash} className="list-item">
              <div>
                {row.rail} · {row.amount_mei} HAC
              </div>
              <div className="muted">{row.summary}</div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}