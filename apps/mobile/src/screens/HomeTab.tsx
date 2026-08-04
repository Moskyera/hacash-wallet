import type { TouchEvent } from "react";
import { useLocale } from "@hacash/wallet-ui";
import type { AssetSummary } from "../api";
import BalanceOverview from "../components/BalanceOverview";

type Props = {
  assets: AssetSummary | null;
  hideBalances: boolean;
  refreshing: boolean;
  watchOnly: boolean;
  onPullStart: (e: TouchEvent) => void;
  onPullMove: (e: TouchEvent) => void;
  onPullEnd: () => void;
  onAirgap: () => void;
  onChat: () => void;
  onHacd: () => void;
  onOpenFastPay: () => void;
};

export default function HomeTab({
  assets,
  hideBalances,
  refreshing,
  watchOnly,
  onPullStart,
  onPullMove,
  onPullEnd,
  onAirgap,
  onChat,
  onHacd,
  onOpenFastPay,
}: Props) {
  const { t } = useLocale();
  const primaryActions = !watchOnly ? (
    <section className="mobile-primary-actions" aria-label="Wallet menu">
      <QuickAction kind="airgap" label={t("more.airgap")} onClick={onAirgap} primary />
      <QuickAction kind="chat" label={t("nav.messages")} onClick={onChat} />
      <QuickAction kind="hacd" label="My HACD" onClick={onHacd} />
      <QuickAction kind="fastpay" label="Fast Pay" onClick={onOpenFastPay} />
    </section>
  ) : null;

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
    </div>
  );
}

type QuickKind = "airgap" | "chat" | "hacd" | "fastpay";

function QuickAction({ kind, label, onClick, primary = false }: { kind: QuickKind; label: string; onClick: () => void; primary?: boolean }) {
  return (
    <button type="button" className={`quick-action${primary ? " primary-action" : ""}`} onClick={onClick}>
      <QuickIcon kind={kind} />
      <span>{label}</span>
    </button>
  );
}

function QuickIcon({ kind }: { kind: QuickKind }) {
  const path = kind === "airgap"
    ? "M7 3h10v18H7zM10 6h4M9 17h6M3 8l3 3-3 3M21 8l-3 3 3 3"
    : kind === "chat"
      ? "M5 5h14v11H9l-4 4V5zM8 9h8M8 12h5"
      : kind === "hacd"
        ? "m12 3 7 6-7 12L5 9l7-6zM5 9h14M9 9l3 12 3-12"
        : "m13 2-8 12h7l-1 8 8-12h-7l1-8z";
  return <svg className="quick-action-icon" viewBox="0 0 24 24" aria-hidden><path d={path} /></svg>;
}