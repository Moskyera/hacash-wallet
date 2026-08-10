import type { TouchEvent } from "react";
import { useLocale } from "@hacash/wallet-ui";
import type { AssetSummary, TxRecord, WalletStatus } from "../api";
import BalanceOverview from "../components/BalanceOverview";
import { formatHacMei } from "../privacy";

type Props = {
  assets: AssetSummary | null;
  status: WalletStatus | null;
  history: TxRecord[];
  hideBalances: boolean;
  refreshing: boolean;
  watchOnly: boolean;
  fastPayReady: boolean;
  onPullStart: (e: TouchEvent) => void;
  onPullMove: (e: TouchEvent) => void;
  onPullEnd: () => void;
  onSend: () => void;
  onReceive: () => void;
  onHacd: () => void;
  onOpenFastPay: () => void;
  onOpenHistory: () => void;
  onOpenAgent?: () => void;
};

export default function HomeTab({
  assets,
  status,
  history,
  hideBalances,
  refreshing,
  watchOnly,
  fastPayReady,
  onPullStart,
  onPullMove,
  onPullEnd,
  onSend,
  onReceive,
  onHacd,
  onOpenFastPay,
  onOpenHistory,
  onOpenAgent,
}: Props) {
  const { t } = useLocale();
  /*
   * Send and Receive lead, because those are what someone opens a wallet to do
   * and neither had a button on this screen before. Air-gap signing and the
   * messenger, which used to sit here, keep their entries under Menu: they are
   * occasional tools rather than the two actions the home screen exists for.
   *
   * Receive stays available to a watch-only wallet. It cannot spend, but an
   * address it can show is precisely what it is for.
   */
  const primaryActions = (
    <section className="mobile-primary-actions" aria-label="Wallet actions">
      {!watchOnly ? (
        <QuickAction kind="send" label={t("nav.send")} onClick={onSend} primary />
      ) : null}
      <QuickAction kind="receive" label={t("nav.receive")} onClick={onReceive} />
      <QuickAction kind="hacd" label="My HACD" onClick={onHacd} />
      {!watchOnly ? <QuickAction kind="fastpay" label="Fast Pay" onClick={onOpenFastPay} /> : null}
    </section>
  );

  return (
    <div className="mobile-home-dashboard">
      <div
        className={`balance-hero ${refreshing ? "pulling" : ""}`}
        onTouchStart={onPullStart}
        onTouchMove={onPullMove}
        onTouchEnd={onPullEnd}
      >
        <BalanceOverview
          assets={assets}
          hideBalances={hideBalances}
          actions={primaryActions}
          topHint={
            <p className="muted pull-hint">
              {refreshing ? t("home.refreshing") : t("home.pullToRefresh")}
            </p>
          }
        />
      </div>

      <section className="mobile-home-card mobile-activity-card">
        <header className="mobile-home-card-heading">
          <h2>Recent activity</h2>
          <button type="button" onClick={onOpenHistory}>View all</button>
        </header>
        {history.length === 0 ? (
          <p className="mobile-home-empty">No wallet activity recorded on this device.</p>
        ) : (
          <div className="mobile-activity-list">
            {history.slice(0, 4).map((row) => (
              <div className="mobile-activity-row" key={`${row.tx_hash}-${row.timestamp}`}>
                <span className={`activity-mark activity-${row.status ?? "pending"}`} aria-hidden>
                  {row.rail === "fast_pay" ? "FP" : "L1"}
                </span>
                <div>
                  <strong>{row.summary || row.rail}</strong>
                  <small>{row.timestamp}</small>
                </div>
                <span className="activity-amount">{formatHacMei(row.amount_mei)} HAC</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <div className="mobile-home-card-pair">
        <section className="mobile-home-card">
          <header className="mobile-home-card-heading">
            <h2>Fast Pay status</h2>
          </header>
          <p className={`mobile-home-state ${fastPayReady ? "ready" : ""}`}>
            {fastPayReady ? "Ready to send" : "Setup required"}
          </p>
          <p className="mobile-home-note">
            {status?.channel_id ? "Channel open" : "No channel configured"}
            {status?.l2_enabled ? " · L2 enabled" : " · L1 only"}
          </p>
          {!watchOnly ? (
            <button type="button" className="mobile-home-action" onClick={onOpenFastPay}>
              Manage Fast Pay
            </button>
          ) : null}
        </section>

        {/*
          The Agent Wallet, seen from the phone.
          No balance, no spend figure and no pending count: reading any of those
          needs the Agent Wallet's own key, which this space does not hold. What
          it can honestly offer is the way in, and what the phone is for once it
          gets there.
        */}
        {onOpenAgent ? (
          <section className="mobile-home-card mobile-agent-card">
            <header className="mobile-home-card-heading">
              <h2>AI Agent Wallet</h2>
            </header>
            <p className="mobile-home-note">
              A separate wallet with its own key and its own limits. This phone can see its
              status and approve one payment at a time. It never holds its key.
            </p>
            <button type="button" className="mobile-home-action primary" onClick={onOpenAgent}>
              Open AI Agent Wallet
            </button>
          </section>
        ) : null}
      </div>
    </div>
  );
}

type QuickKind = "send" | "receive" | "hacd" | "fastpay";

function QuickAction({ kind, label, onClick, primary = false }: { kind: QuickKind; label: string; onClick: () => void; primary?: boolean }) {
  return (
    <button type="button" className={`quick-action${primary ? " primary-action" : ""}`} onClick={onClick}>
      <QuickIcon kind={kind} />
      <span>{label}</span>
    </button>
  );
}

function QuickIcon({ kind }: { kind: QuickKind }) {
  const path = kind === "send"
    ? "M12 20V5M6 11l6-6 6 6"
    : kind === "receive"
      ? "M12 4v15M6 13l6 6 6-6"
      : kind === "hacd"
        ? "m12 3 7 6-7 12L5 9l7-6zM5 9h14M9 9l3 12 3-12"
        : "m13 2-8 12h7l-1 8 8-12h-7l1-8z";
  return <svg className="quick-action-icon" viewBox="0 0 24 24" aria-hidden><path d={path} /></svg>;
}