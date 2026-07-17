import type { TouchEvent } from "react";
import type { AssetSummary, FastPayStatus, TxRecord } from "../api";
import BalanceOverview from "../components/BalanceOverview";
import HacdLaunchpadIcon from "../components/HacdLaunchpadIcon";
import TxStatusMark from "../components/TxStatusMark";
import { fastPayStatusLine, fastPayStatusTitle } from "../fastPayUi";
import { formatHacMei } from "../privacy";
import { openTxInExplorer } from "../txHistory";

type Props = {
  assets: AssetSummary | null;
  hideBalances: boolean;
  refreshing: boolean;
  fastPay: FastPayStatus | null;
  watchOnly: boolean;
  busy: boolean;
  history: TxRecord[];
  onPullStart: (e: TouchEvent) => void;
  onPullMove: (e: TouchEvent) => void;
  onPullEnd: () => void;
  onEnableFastPay: () => void;
  onDisableFastPay: () => void;
  onScanPay: () => void;
  onReceive: () => void;
  onContacts: () => void;
  onHistory: () => void;
  onQuantum: () => void;
  onLaunchpad: () => void;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
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
  onDisableFastPay,
  onScanPay,
  onReceive,
  onContacts,
  onHistory,
  onQuantum,
  onLaunchpad,
  onToast,
}: Props) {
  return (
    <>
      <div
        className={`balance-hero ${refreshing ? "pulling" : ""}`}
        onTouchStart={onPullStart}
        onTouchMove={onPullMove}
        onTouchEnd={onPullEnd}
      >
        <BalanceOverview
          assets={assets}
          hideBalances={hideBalances}
          topHint={<p className="muted pull-hint">{refreshing ? "Refreshing…" : "Pull down to refresh"}</p>}
        />
      </div>

      {fastPay && (
        <div className={`fp-banner${fastPay.state === "ready" ? " on" : ""}`}>
          <div className="fp-banner-status">
            {fastPay.state === "ready" ? (
              <span className="badge badge-ok">Fast Pay on</span>
            ) : (
              <strong>{fastPayStatusTitle(fastPay.state)}</strong>
            )}
            <p className="muted">
              {fastPayStatusLine(fastPay.state, fastPay.default_deposit_mei ?? 10)}
            </p>
          </div>
          {!watchOnly && fastPay.state !== "ready" && fastPay.can_enable && (
            <button type="button" className="primary" disabled={busy} onClick={() => void onEnableFastPay()}>
              Enable
            </button>
          )}
          {!watchOnly && fastPay.state === "ready" && (
            <button type="button" disabled={busy} onClick={() => void onDisableFastPay()}>
              Disable
            </button>
          )}
        </div>
      )}

      {!watchOnly && (
        <div className="quick-actions">
          <button type="button" className="quick-action primary-action" onClick={onScanPay}>
            <span className="icon" aria-hidden>⌗</span>
            Scan & Pay
          </button>
          <button type="button" className="quick-action" onClick={onReceive}>
            <span className="icon" aria-hidden>↓</span>
            Receive
          </button>
          <button type="button" className="quick-action" onClick={onContacts}>
            <span className="icon" aria-hidden>◎</span>
            Contacts
          </button>
          <button type="button" className="quick-action" onClick={onHistory}>
            <span className="icon" aria-hidden>≡</span>
            History
          </button>
          <button type="button" className="quick-action" onClick={onQuantum}>
            <span className="icon" aria-hidden>◇</span>
            Quantum
          </button>
          <button type="button" className="quick-action" onClick={onLaunchpad}>
            <span className="icon" aria-hidden>
              <HacdLaunchpadIcon />
            </span>
            HACD Apps
          </button>
        </div>
      )}

      {history.length > 0 && (
        <div className="card card-flat">
          <h2>Recent</h2>
          {history.slice(0, 3).map((row) => (
            <button
              key={`${row.tx_hash}-${row.timestamp}`}
              type="button"
              className="list-item list-item-row list-item-tap"
              onClick={() => void openTxInExplorer(row, onToast)}
            >
              <TxStatusMark status={row.status} />
              <div className="list-item-body">
                <div>
                  {row.rail} · {formatHacMei(row.amount_mei)} HAC
                </div>
                <div className="muted">{row.summary}</div>
              </div>
            </button>
          ))}
        </div>
      )}
    </>
  );
}