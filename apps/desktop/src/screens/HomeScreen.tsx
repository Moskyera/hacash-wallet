import { HowItWorksPrompt } from "@hacash/wallet-ui";
import { open } from "@tauri-apps/plugin-shell";

import type { AssetSummary, PrivacySettings, TxRecord, WalletStatus } from "../api";
import type { AssetTrendHistory } from "../assetTrends";
import BalanceOverview from "../components/BalanceOverview";
import HacdDappConnect from "../components/HacdDappConnect";
import { formatInvokeError } from "../formatInvokeError";
import { useLocale } from "../locale";
import { formatHacMei, maskHash } from "../privacy";
import { formatCountdown, type Screen } from "./types";

type Props = {
  status: WalletStatus | null;
  assets: AssetSummary | null;
  assetTrends: AssetTrendHistory;
  history: TxRecord[];
  hideBalances: boolean;
  hideAddresses: boolean;
  fastPayReady: boolean;
  lastTx: string;
  privacy: PrivacySettings;
  onNavigate: (screen: Screen) => void;
  onOpenAgent: () => void;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
  clearMessages: () => void;
};

export default function HomeScreen({
  status,
  assets,
  assetTrends,
  history,
  hideBalances,
  hideAddresses,
  fastPayReady,
  lastTx,
  privacy,
  onNavigate,
  onOpenAgent,
  onNotify,
  clearMessages,
}: Props) {
  const { t } = useLocale();

  return (
    <section className="dashboard-page">
      <HowItWorksPrompt
        copy={{
          title: t("docs.readPromptTitle"),
          body: t("docs.readPromptBody"),
          open: t("docs.howItWorks"),
          later: t("docs.readPromptLater"),
          never: t("docs.readPromptNever"),
        }}
        openExternal={open}
        onError={(error) => onNotify(formatInvokeError(error), "error")}
      />

      <div className="dashboard-grid">
        <article className="dashboard-card dashboard-portfolio-card">
          <BalanceOverview
            assets={assets}
            trends={assetTrends}
            hideBalances={hideBalances}
          />
          <div className="portfolio-meta">
            <span>Privacy {privacy.hide_balances || privacy.hide_addresses ? "on" : "standard"}</span>
            {status?.seconds_until_lock != null ? (
              <span>Auto-lock {formatCountdown(status.seconds_until_lock)}</span>
            ) : null}
          </div>
        </article>

      </div>

      <div className="dashboard-panel-row">
        <section className="dashboard-card dashboard-activity-card">
          <DashboardHeading title="Recent activity" action="View all" onAction={() => onNavigate("history")} />
          {history.length === 0 ? (
            <div className="dashboard-empty">No wallet activity recorded on this device.</div>
          ) : (
            <div className="dashboard-activity-list">
              {history.slice(0, 5).map((row) => (
                <div className="dashboard-activity-row" key={`${row.tx_hash}-${row.timestamp}`}>
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

        <section className="dashboard-card dashboard-status-card">
          <DashboardHeading title="Fast Pay status" />
          <StatusLine label="Status" value={fastPayReady ? "Ready" : "Setup required"} ready={fastPayReady} />
          <StatusLine label="Channel" value={status?.channel_id ? "Open" : "Not configured"} ready={Boolean(status?.channel_id)} />
          <StatusLine label="Route" value={status?.l2_enabled ? "L2 enabled" : "L1 only"} ready={Boolean(status?.l2_enabled)} />
          {!status?.watch_only ? (
            <button type="button" className="dashboard-text-action" onClick={() => onNavigate("fastpay")}>Manage Fast Pay</button>
          ) : null}
        </section>

        <section className="dashboard-card dashboard-status-card">
          <DashboardHeading title="Security status" />
          <StatusLine label="Encrypted vault" value={status?.locked ? "Locked" : "Active"} ready={!status?.locked} />
          <StatusLine label="Security profile" value={status?.security_profile ?? "Unavailable"} ready={Boolean(status?.security_profile)} />
          <StatusLine label="Signing" value={signingLabel(status)} ready={Boolean(status?.signing_available)} />
          <StatusLine label="Privacy" value={privacy.screen_privacy ? "Protected" : "Standard"} ready={privacy.screen_privacy} />
          <button type="button" className="dashboard-text-action" onClick={() => onNavigate("security")}>Review security</button>
        </section>

        <AgentWalletCard onOpenAgent={onOpenAgent} />
      </div>

      {lastTx ? (
        <div className="success-box dashboard-last-tx">
          Last transaction: <code>{maskHash(lastTx, hideAddresses)}</code>
        </div>
      ) : null}

      <div className="dashboard-dapp-card">
        <HacdDappConnect
          watchOnly={status?.watch_only}
          pauseAutoLockDapp={privacy.pause_auto_lock_dapp ?? true}
          onNotify={(msg, kind) => {
            clearMessages();
            onNotify(msg, kind);
          }}
        />
      </div>
    </section>
  );
}

/**
 * The Agent Wallet, seen from My Wallet.
 *
 * This card cannot show an agent balance, a spend figure or a pending-approval
 * count, and does not pretend to. Reading any of that needs the Agent Wallet's
 * own key, and the two spaces never hold an unlock session at the same time.
 *
 * It also states the consequence of the button, which is the one thing someone
 * on this screen cannot guess: going there locks this wallet.
 */
function AgentWalletCard({ onOpenAgent }: { onOpenAgent: () => void }) {
  return (
    <section className="dashboard-card dashboard-agent-card">
      <DashboardHeading title="AI Agent Wallet" />
      <div className="dashboard-agent-body">
        <span className="dashboard-agent-mark" aria-hidden>
          <svg viewBox="0 0 24 24" role="presentation">
            <rect x="4" y="7" width="16" height="12" rx="3" />
            <circle cx="9.5" cy="13" r="1.4" />
            <circle cx="14.5" cy="13" r="1.4" />
            <path d="M12 7V4" />
            <circle cx="12" cy="3" r="1.1" />
          </svg>
        </span>
        <p className="dashboard-agent-copy">
          A separate wallet with its own key and its own spending limits, for payments an
          AI agent asks you to approve.
        </p>
      </div>
      <button type="button" className="dashboard-agent-open" onClick={onOpenAgent}>
        Open AI Agent Wallet
      </button>
      <p className="dashboard-agent-note">
        Opening it locks My Wallet. The two never share a key, a passphrase or an unlock
        session, so only one is open at a time.
      </p>
    </section>
  );
}

function DashboardHeading({ title, action, onAction }: { title: string; action?: string; onAction?: () => void }) {
  return (
    <div className="dashboard-card-heading">
      <h2>{title}</h2>
      {action && onAction ? <button type="button" onClick={onAction}>{action}</button> : null}
    </div>
  );
}

function StatusLine({ label, value, ready }: { label: string; value: string; ready: boolean }) {
  return (
    <div className="dashboard-status-line">
      <span>{label}</span>
      <strong className={ready ? "ready" : "neutral"}>{value}</strong>
    </div>
  );
}

function signingLabel(status: WalletStatus | null): string {
  if (!status) return "Unavailable";
  if (status.hardware_signing_mode === "airgap_only") return "Cold Vault";
  if (status.hardware_signing_mode === "webauthn_gate") return "WebAuthn gated";
  if (status.watch_only) return "Watch only";
  return status.signing_available ? "Local signing" : "Unavailable";
}