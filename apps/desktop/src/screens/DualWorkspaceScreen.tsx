import { useEffect, useState } from "react";

import type { AssetSummary, PrivacySettings, WalletStatus } from "../api";
import type { AssetTrendHistory } from "../assetTrends";
import { agentWalletApi, type AgentRuntimeStatus } from "../agent/api";
import BalanceOverview from "../components/BalanceOverview";
import { maskAddress } from "../privacy";
import type { Screen } from "./types";

type Props = {
  status: WalletStatus | null;
  assets: AssetSummary | null;
  assetTrends: AssetTrendHistory;
  hideBalances: boolean;
  hideAddresses: boolean;
  privacy: PrivacySettings;
  onNavigate: (screen: Screen) => void;
  onOpenAgent: () => void;
};

/**
 * My Wallet and the Agent Wallet, side by side.
 *
 * WHAT THE RIGHT COLUMN CAN AND CANNOT SAY
 * The two spaces never hold an unlock session at the same time, by design, and
 * that property is kept here rather than traded away for a fuller-looking
 * screen. So the agent column shows only what can be read without the Agent
 * Wallet's key: whether one exists, its address, when it was created, and
 * whether its connector is currently listening.
 *
 * It shows no balance, no spending limit, no spend total and no pending
 * approvals, because every one of those needs the key this space does not hold.
 * It also does not report whether agent payments are stopped: that marker is
 * not in the registry-level status either, and guessing it here would be worse
 * than leaving it out, since someone would read a wrong answer as reassurance.
 */
export default function DualWorkspaceScreen({
  status,
  assets,
  assetTrends,
  hideBalances,
  hideAddresses,
  privacy,
  onNavigate,
  onOpenAgent,
}: Props) {
  const [runtime, setRuntime] = useState<AgentRuntimeStatus | null>(null);
  const [runtimeError, setRuntimeError] = useState("");

  useEffect(() => {
    let cancelled = false;
    agentWalletApi
      .runtimeStatus()
      .then((next) => {
        if (cancelled) return;
        // An empty reply is a failure, not a slow success. Without this the
        // column sits on "Reading Agent Wallet status." for ever and offers
        // nothing to do about it.
        if (next == null || !Array.isArray(next.wallets)) {
          setRuntimeError("Agent Wallet status could not be read.");
          return;
        }
        setRuntime(next);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setRuntimeError(
          error instanceof Error ? error.message : "Agent Wallet status could not be read.",
        );
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const wallet = runtime?.wallets[0] ?? null;
  const connectorRunning = runtime?.connector.phase === "running";

  return (
    <section className="dashboard-page workspace-page">
      <p className="workspace-guarantee">
        <strong>Separate by construction.</strong> The Agent Wallet has its own key, its own
        passphrase and its own vault. It cannot read or spend from My Wallet, and no agent or
        paired phone can reach this wallet.
      </p>

      <div className="workspace-columns">
        <section className="dashboard-card workspace-column">
          <header className="workspace-column-head">
            <h2>My Wallet</h2>
            <span className="workspace-tag">Open</span>
          </header>
          <BalanceOverview assets={assets} trends={assetTrends} hideBalances={hideBalances} />
          <div className="workspace-actions">
            <button type="button" onClick={() => onNavigate("send")}>Send</button>
            <button type="button" onClick={() => onNavigate("receive")}>Receive</button>
            <button type="button" onClick={() => onNavigate("fastpay")}>Fast Pay</button>
            <button type="button" onClick={() => onNavigate("history")}>History</button>
          </div>
          <p className="workspace-note">
            Privacy {privacy.hide_balances || privacy.hide_addresses ? "on" : "standard"}
            {status?.address ? ` · ${maskAddress(status.address, hideAddresses)}` : ""}
          </p>
        </section>

        <section className="dashboard-card workspace-column workspace-column-agent">
          <header className="workspace-column-head">
            <h2>AI Agent Wallet</h2>
            <span className="workspace-tag workspace-tag-locked">Locked</span>
          </header>

          {runtimeError ? (
            <p className="workspace-note">{runtimeError}</p>
          ) : runtime == null ? (
            <p className="workspace-note">Reading Agent Wallet status.</p>
          ) : !runtime.pilot_enabled ? (
            <p className="workspace-note">
              The Agent Wallet is not included in this build.
            </p>
          ) : wallet == null ? (
            <p className="workspace-note">
              No Agent Wallet has been created yet. Opening the space is where one is made.
            </p>
          ) : (
            <dl className="workspace-facts">
              <div>
                <dt>Address</dt>
                <dd>{maskAddress(wallet.address, hideAddresses)}</dd>
              </div>
              <div>
                <dt>Created</dt>
                <dd>{new Date(wallet.created_at_unix * 1000).toISOString().slice(0, 10)}</dd>
              </div>
              <div>
                <dt>Connector</dt>
                <dd className={connectorRunning ? "ready" : ""}>
                  {connectorRunning ? "Listening" : "Not listening"}
                </dd>
              </div>
            </dl>
          )}

          <button type="button" className="dashboard-agent-open" onClick={onOpenAgent}>
            Open AI Agent Wallet
          </button>
          <p className="workspace-note">
            Balance, limits and pending approvals are not shown here. Reading them needs the
            Agent Wallet&apos;s own key, and opening it locks My Wallet so that only one wallet
            is ever unlocked at a time.
          </p>
        </section>
      </div>
    </section>
  );
}
