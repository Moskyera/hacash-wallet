import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-shell";
import { AGENT_WALLET_HOW_IT_WORKS_URL } from "@hacash/wallet-ui";
import WalletLogo from "../components/WalletLogo";
import MobileCompanionPanel, {
  EMPTY_COMPANION_SNAPSHOT,
  type CompanionActions,
  type CompanionSnapshot,
} from "./MobileCompanionPanel";
import AgentAdminPages from "./AgentAdminPages";
import {
  agentWalletApi,
  type AgentConnectorStatus,
  type AgentPermission,
  type AgentRuntimeStatus,
  type AgentWalletOverview,
  type AgentWalletRegistryEntry,
  type PairingActivation,
  type PendingPairing,
} from "./api";
import {
  HPAY_LOCAL_PILOT,
  WRITE_BLOCKER_LABELS,
  agentWalletLocalEnableBlockers,
  agentWalletPairingBlockers,
  agentWalletPaymentBlockers,
  agentWalletUiState,
  emergencyStopControl,
  type AgentWalletWriteReadiness,
} from "./access";
import { connectorStatusForWallet } from "./controlSafety";
import { DESKTOP_CONTROLS, type DesktopControlId } from "./desktopControls";
import { EMERGENCY_STOP_WARNING } from "./irreversibleActions";
import {
  nodeAlertState,
  overviewAlerts,
  overviewBlockOrder,
  phoneLinkState,
  type ConnectorState,
  type NodeState,
  type OverviewAlert,
  type OverviewBlockId,
} from "./overviewLayout";
import "./agent-wallet.css";

type AgentPage =
  | "overview"
  | "agents"
  | "rules"
  | "activity"
  | "providers"
  | "security";

const PAGE_MARKS: Record<AgentPage, string> = {
  overview: "O",
  agents: "A",
  rules: "R",
  activity: "H",
  providers: "P",
  security: "S",
};

const PAGE_LABELS: Record<AgentPage, string> = {
  overview: "Overview",
  agents: "Agents",
  rules: "Rules",
  activity: "Activity",
  providers: "Providers",
  security: "Security",
};

export default function AgentWalletApp({
  onOpenPersonal,
}: {
  onOpenPersonal: () => void;
}) {
  const [runtime, setRuntime] = useState<AgentRuntimeStatus | null>(null);
  const [selected, setSelected] = useState<AgentWalletRegistryEntry | null>(null);
  const [overview, setOverview] = useState<AgentWalletOverview | null>(null);
  const [page, setPage] = useState<AgentPage>("overview");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [pairingActivation, setPairingActivation] =
    useState<PairingActivation | null>(null);
  const [pendingPairing, setPendingPairing] =
    useState<PendingPairing | null>(null);
  const [companion, setCompanion] = useState<CompanionSnapshot>(
    EMPTY_COMPANION_SNAPSHOT,
  );
  const companionActions = useRef<CompanionActions>({
    turnOn: null,
    startPairing: null,
  });

  const refreshRuntime = useCallback(async () => {
    const next = await agentWalletApi.runtimeStatus();
    setRuntime(next);
    setSelected((current) => {
      if (current) {
        return next.wallets.find((wallet) => wallet.wallet_id === current.wallet_id) ?? null;
      }
      return next.wallets[0] ?? null;
    });
  }, []);

  const refreshOverview = useCallback(async () => {
    if (!selected) return;
    const next = await agentWalletApi.overview(selected.wallet_id);
    setOverview(next);
  }, [selected]);

  useEffect(() => {
    void refreshRuntime().catch((reason) =>
      setError(readableError(reason)),
    );
  }, [refreshRuntime]);

  useEffect(() => {
    if (!selected) {
      setOverview(null);
      return;
    }
    void refreshOverview().catch((reason) => {
      const message = readableError(reason);
      if (message.toLowerCase().includes("locked")) setOverview(null);
      else setError(message);
    });
  }, [selected, refreshOverview]);

  useEffect(() => {
    if (!overview?.unlocked) return;
    const timer = window.setInterval(() => {
      void refreshOverview().catch(() => undefined);
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [overview?.unlocked, refreshOverview]);

  const run = useCallback(async (work: () => Promise<void>) => {
    setBusy(true);
    setError("");
    setInfo("");
    try {
      await work();
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setBusy(false);
    }
  }, []);
  const uiState = agentWalletUiState(runtime, overview);

  if (uiState === "loading") {
    return (
      <AgentShell onOpenPersonal={onOpenPersonal}>
        <section className="agent-center-card">
          <h1>AI Agent Wallet</h1>
          <p>Loading the isolated Agent Wallet security domain.</p>
        </section>
      </AgentShell>
    );
  }

  if (!runtime) return null;

  if (uiState === "unavailable_in_this_build") {
    return (
      <AgentShell onOpenPersonal={onOpenPersonal}>
        <section className="agent-center-card">
          <h1>AI Agent Wallet unavailable in this build</h1>
          <p>AI Agent Wallet Testnet Pilot is not enabled in this build.</p>
          <p>Use an HPAY pilot build to access Agent Wallet testing.</p>
          <p className="agent-safe-note">
            Backend feature: disabled. My Wallet is unaffected.
          </p>
          <button type="button" onClick={onOpenPersonal}>
            {DESKTOP_CONTROLS.back_to_wallet_selection}
          </button>
        </section>
      </AgentShell>
    );
  }

  if (uiState === "recovery_required") {
    return (
      <AgentShell onOpenPersonal={onOpenPersonal}>
        <section className="agent-center-card">
          <h1>AI Agent Wallet recovery required</h1>
          <p>{runtime.error ?? "The Agent Wallet could not be initialized."}</p>
          <p className="agent-safe-note">
            My Wallet is unaffected and remains available.
          </p>
          {/* This screen had no control at all. Both of these already existed
              elsewhere; the dead end was that neither was rendered here. */}
          <div className="agent-control-row">
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await refreshRuntime();
                })
              }
            >
              {DESKTOP_CONTROLS.try_again}
            </button>
            <button type="button" onClick={onOpenPersonal}>
              {DESKTOP_CONTROLS.back_to_wallet_selection}
            </button>
          </div>
        </section>
      </AgentShell>
    );
  }

  if (uiState === "not_created") {
    return (
      <AgentShell onOpenPersonal={onOpenPersonal}>
        <CreateAgentWallet
          busy={busy}
          error={error}
          onCreate={(input) =>
            run(async () => {
              const created = await agentWalletApi.create(
                input.passphrase,
                input.networkMode,
                input.nodeUrl,
                input.blockOneFingerprint,
              );
              setInfo(`Agent Wallet ${created.address} was created and remains locked.`);
              await refreshRuntime();
            })
          }
        />
      </AgentShell>
    );
  }

  if (uiState === "locked" || !overview?.unlocked) {
    return (
      <AgentShell onOpenPersonal={onOpenPersonal}>
        <UnlockAgentWallet
          wallets={runtime.wallets}
          selected={selected}
          busy={busy}
          error={error}
          info={info}
          onSelect={setSelected}
          onUnlock={(passphrase) =>
            run(async () => {
              if (!selected) return;
              await agentWalletApi.unlock(selected.wallet_id, passphrase);
              await refreshOverview();
            })
          }
        />
      </AgentShell>
    );
  }
  // Three separate questions, three separate answers. Reusing the payment
  // answer for the other two is what deadlocked this wallet: the stop could not
  // be cleared without a paired phone, and no phone could be paired while the
  // stop was engaged.
  const paymentBlockers = agentWalletPaymentBlockers(runtime, overview);
  const localEnableBlockers = agentWalletLocalEnableBlockers(runtime, overview);
  const pairingBlockers = agentWalletPairingBlockers(runtime, overview);

  const lockAgentWallet = () =>
    run(async () => {
      await agentWalletApi.lock(overview.wallet_id);
      setOverview(null);
    });

  return (
    <div className="agent-app">
      <aside className="agent-sidebar">
        <div className="agent-brand">
          <WalletLogo size="sm" />
          <div>
            <strong>HPAY</strong>
            <span>AI Agent Wallet</span>
          </div>
        </div>
        <div className="wallet-space-switcher" role="group" aria-label="Wallet space">
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              run(async () => {
                await agentWalletApi.lock(overview.wallet_id);
                setOverview(null);
                onOpenPersonal();
              })
            }
          >
            My Wallet
          </button>
          <span className="wallet-space-current active" aria-current="page">
            AI Agent Wallet
          </span>
        </div>
        <nav aria-label="AI Agent Wallet">
          {(Object.keys(PAGE_LABELS) as AgentPage[]).map((id) => (
            <button
              key={id}
              type="button"
              className={page === id ? "active" : ""}
              onClick={() => setPage(id)}
            >
              <span className="agent-nav-mark" aria-hidden>{PAGE_MARKS[id]}</span>
              <span>{PAGE_LABELS[id]}</span>
            </button>
          ))}
        </nav>
        <div className="agent-sidebar-foot">
          <span>{shortAddress(overview.address)}</span>
          <span>{overview.network_mode}</span>
          <button
            type="button"
            className="agent-inline-link"
            onClick={() => void open(AGENT_WALLET_HOW_IT_WORKS_URL).catch(() => undefined)}
          >
            How the Agent Wallet works
          </button>
          <button type="button" disabled={busy} onClick={() => void lockAgentWallet()}>
            Lock Agent Wallet
          </button>
        </div>
      </aside>
      <main className="agent-content">
        <PilotBanner />
        {error && <div className="alert" role="alert">{error}</div>}
        {info && <div className="info-box">{info}</div>}
        <AgentPageContent
          page={page}
          overview={overview}
          connector={connectorStatusForWallet(runtime.connector, overview.wallet_id)}
          pairingActivation={pairingActivation}
          pendingPairing={pendingPairing}
          busy={busy}
          run={run}
          onInfo={setInfo}
          onRefresh={refreshOverview}
          paymentBlockers={paymentBlockers}
          localEnableBlockers={localEnableBlockers}
          pairingBlockers={pairingBlockers}
          companion={companion}
          companionActions={companionActions}
          onCompanionSnapshot={setCompanion}
          onOpenPage={setPage}
          onLockAndSwitch={() => void lockAgentWallet()}
          onEmergencyStop={() =>
            run(async () => {
              await agentWalletApi.emergencyStop(overview.wallet_id);
              setInfo("All Agent Wallet payments are disabled.");
              await refreshOverview();
            })
          }
          onEnable={() =>
            run(async () => {
              await agentWalletApi.enablePayments(overview.wallet_id);
              setInfo("Agent payments are enabled. Every payment still requires manual approval.");
              await refreshOverview();
            })
          }
          onStartConnector={() =>
            run(async () => {
              try {
                await agentWalletApi.startRuntime(overview.wallet_id);
                setInfo("The local Agent connector is running.");
              } finally {
                await refreshRuntime();
              }
            })
          }
          onStopConnector={() =>
            run(async () => {
              try {
                await agentWalletApi.stopRuntime(overview.wallet_id);
                setPairingActivation(null);
                setPendingPairing(null);
                setInfo("The local Agent connector is stopped.");
              } finally {
                await refreshRuntime();
              }
            })
          }
          onActivatePairing={() =>
            run(async () => {
              const activation = await agentWalletApi.activatePairing(overview.wallet_id);
              setPairingActivation(activation);
              setPendingPairing(null);
              setInfo("A one-time local pairing code was created.");
            })
          }
          onForgetPairingCode={() => {
            setPairingActivation(null);
            setPendingPairing(null);
            setInfo(
              "The pairing code was cleared from this screen. No agent can be approved with it here, and it expires on its own.",
            );
          }}
          onCheckPairing={() =>
            run(async () => {
              const pending = await agentWalletApi.pendingPairing(overview.wallet_id);
              setPendingPairing(pending);
              setInfo(pending ? "Review the exact local agent identity below." : "No agent has submitted this pairing code yet.");
            })
          }
          onApprovePairing={() =>
            run(async () => {
              if (!pairingActivation || !pendingPairing) {
                throw new Error("Create a pairing code and review a submitted agent first.");
              }
              const readOnly = pendingPairing.requestedCapabilities.filter(
                (permission): permission is AgentPermission =>
                  permission === "read_wallet_info" ||
                  permission === "read_balance" ||
                  permission === "read_own_operation_status" ||
                  permission === "list_own_operations",
              );
              await agentWalletApi.approvePairing(
                overview.wallet_id,
                pairingActivation.pairingId,
                pendingPairing.submissionCommitment,
                {
                  permissions: readOnly,
                  max_per_payment_units: "0",
                  max_daily_units: "0",
                  max_pending_operations: 1,
                  allowed_recipients: [],
                  blocked_recipients: [],
                  approval_mode: "desktop_manual",
                  policy_epoch: 1,
                },
              );
              setPairingActivation(null);
              setPendingPairing(null);
              setInfo("The local agent is paired read-only. Spending remains disabled in Rules.");
              await refreshOverview();
            })
          }
          onRejectPairing={() =>
            run(async () => {
              if (!pairingActivation || !pendingPairing) {
                throw new Error("There is no submitted pairing request to reject.");
              }
              await agentWalletApi.rejectPairing(
                overview.wallet_id,
                pairingActivation.pairingId,
                pendingPairing.submissionCommitment,
              );
              setPairingActivation(null);
              setPendingPairing(null);
              setInfo("The local pairing request was rejected.");
            })
          }
        />
      </main>
    </div>
  );
}

function AgentShell({
  onOpenPersonal,
  children,
}: {
  onOpenPersonal: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="agent-entry">
      <header>
        <WalletLogo size="sm" />
        <div className="wallet-space-switcher" role="group" aria-label="Wallet space">
          <button type="button" onClick={onOpenPersonal}>My Wallet</button>
          <span className="wallet-space-current active" aria-current="page">
            AI Agent Wallet
          </span>
        </div>
      </header>
      <PilotBanner />
      {children}
    </div>
  );
}

function PilotBanner() {
  return (
    <section className="agent-pilot-banner" role="status" aria-label="Agent Wallet network safety">
      <strong>AI AGENT WALLET</strong>
      <span>{HPAY_LOCAL_PILOT.label}</span>
      <span>PRIVATE DEVELOPMENT NETWORK</span>
      <span>NO MAINNET FUNDS</span>
      <code>{HPAY_LOCAL_PILOT.networkInstance}</code>
    </section>
  );
}
function CreateAgentWallet({
  busy,
  error,
  onCreate,
}: {
  busy: boolean;
  error: string;
  onCreate: (input: {
    passphrase: string;
    networkMode: "testnet";
    nodeUrl: string;
    blockOneFingerprint: string;
  }) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const localError = useMemo(() => {
    if (passphrase && passphrase.length < 15) return "Use at least 15 characters.";
    if (confirmation && passphrase !== confirmation) return "Passphrases do not match.";
    return "";
  }, [passphrase, confirmation]);
  return (
    <section className="agent-center-card agent-create">
      <span className="agent-eyebrow">Independent security boundary</span>
      <h1>Create AI Agent Wallet</h1>
      <p>
        This creates a new Hacash address, private key and encrypted vault. It
        never uses or unlocks My Wallet.
      </p>
      {/* A before-the-fact warning. It stays visible; only the background list
          moved behind a disclosure. */}
      <div className="agent-warning">
        Mainnet creation, funding and payments remain blocked until Agent Wallet
        backup and recovery has been independently verified.
      </div>
      <details className="agent-advanced-details">
        <summary>What this wallet can and cannot do</summary>
        <ul>
          <li>Testnet foundation only in this release.</li>
          <li>Every payment requires manual desktop approval.</li>
          <li>Agents never receive a private key or raw signing access.</li>
          <li>Agent L2 Fast Pay is not enabled in this release.</li>
          <li>
            Network kind: {HPAY_LOCAL_PILOT.networkKind}. Profile:{" "}
            {HPAY_LOCAL_PILOT.profileId}. This private chain is not the official
            Hacash testnet.
          </li>
        </ul>
      </details>
      {(error || localError) && <div className="alert">{error || localError}</div>}
      <label>
        Agent Wallet passphrase
        <input
          type="password"
          autoComplete="new-password"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
        />
      </label>
      <label>
        Confirm passphrase
        <input
          type="password"
          autoComplete="new-password"
          value={confirmation}
          onChange={(event) => setConfirmation(event.target.value)}
        />
      </label>
      <details className="agent-advanced-details">
        <summary>Network settings</summary>
        <label>
          Network
          <input value={HPAY_LOCAL_PILOT.label} readOnly />
        </label>
        <label>
          Local Pilot node API
          <input value={HPAY_LOCAL_PILOT.nodeUrl} readOnly />
        </label>
        <label>
          Local Pilot block 1 fingerprint
          <input
            value={HPAY_LOCAL_PILOT.blockOne}
            inputMode="text"
            autoComplete="off"
            spellCheck={false}
            maxLength={64}
            readOnly
          />
        </label>
      </details>
      <button
        type="button"
        className="agent-primary"
        disabled={
          busy ||
          passphrase.length < 15 ||
          passphrase !== confirmation
        }
        onClick={() =>
          onCreate({
            passphrase,
            networkMode: "testnet",
            nodeUrl: HPAY_LOCAL_PILOT.nodeUrl,
            blockOneFingerprint: HPAY_LOCAL_PILOT.blockOne,
          })
        }
      >
        {busy ? "Creating encrypted vault..." : "Create Local Pilot Agent Wallet"}
      </button>
    </section>
  );
}
function UnlockAgentWallet({
  wallets,
  selected,
  busy,
  error,
  info,
  onSelect,
  onUnlock,
}: {
  wallets: AgentWalletRegistryEntry[];
  selected: AgentWalletRegistryEntry | null;
  busy: boolean;
  error: string;
  info: string;
  onSelect: (wallet: AgentWalletRegistryEntry) => void;
  onUnlock: (passphrase: string) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  return (
    <section className="agent-center-card">
      <span className="agent-eyebrow">Desktop primary signer</span>
      <h1>Unlock AI Agent Wallet</h1>
      <p>Unlocking this space does not unlock My Wallet.</p>
      {error && <div className="alert">{error}</div>}
      {info && <div className="info-box">{info}</div>}
      <label>
        Agent Wallet
        <select
          value={selected?.wallet_id ?? ""}
          onChange={(event) => {
            const wallet = wallets.find((item) => item.wallet_id === event.target.value);
            if (wallet) onSelect(wallet);
          }}
        >
          {wallets.map((wallet) => (
            <option key={wallet.wallet_id} value={wallet.wallet_id}>
              {shortAddress(wallet.address)}
            </option>
          ))}
        </select>
      </label>
      <label>
        Agent Wallet passphrase
        <input
          type="password"
          autoComplete="current-password"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && passphrase) onUnlock(passphrase);
          }}
        />
      </label>
      <button
        type="button"
        className="agent-primary"
        disabled={busy || !selected || !passphrase}
        onClick={() => onUnlock(passphrase)}
      >
        {busy ? "Unlocking..." : "Unlock Agent Wallet"}
      </button>
    </section>
  );
}

type PageContentProps = {
  page: AgentPage;
  overview: AgentWalletOverview;
  connector: AgentConnectorStatus | null;
  pairingActivation: PairingActivation | null;
  pendingPairing: PendingPairing | null;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
  onRefresh: () => Promise<void>;
  /** Gates decision 1 only: making a payment. */
  paymentBlockers: AgentWalletWriteReadiness[];
  /** Gates decision 2 only: clearing the emergency stop from this desktop. */
  localEnableBlockers: AgentWalletWriteReadiness[];
  /** Gates decision 3 only: pairing a phone. */
  pairingBlockers: AgentWalletWriteReadiness[];
  companion: CompanionSnapshot;
  companionActions: React.MutableRefObject<CompanionActions>;
  onCompanionSnapshot: (snapshot: CompanionSnapshot) => void;
  onOpenPage: (page: AgentPage) => void;
  onLockAndSwitch: () => void;
  onEmergencyStop: () => void;
  onEnable: () => void;
  onStartConnector: () => void;
  onStopConnector: () => void;
  onActivatePairing: () => void;
  onForgetPairingCode: () => void;
  onCheckPairing: () => void;
  onApprovePairing: () => void;
  onRejectPairing: () => void;
};

function AgentPageContent(props: PageContentProps) {
  const {
    page,
    overview,
    connector,
    busy,
    run,
    onInfo,
    onRefresh,
    paymentBlockers,
    localEnableBlockers,
    pairingBlockers,
    companion,
    companionActions,
    onCompanionSnapshot,
    onOpenPage,
    onLockAndSwitch,
    onEmergencyStop,
    onEnable,
    onStartConnector,
    onStopConnector,
  } = props;

  if (page !== "overview") {
    return (
      <AgentAdminPages
        page={page}
        overview={overview}
        busy={busy}
        run={run}
        onInfo={onInfo}
        onRefreshOverview={onRefresh}
        onEmergencyStop={onEmergencyStop}
        onEnable={onEnable}
        localEnableBlockers={localEnableBlockers}
        onOpenPage={onOpenPage}
      />
    );
  }

  const stopControl = emergencyStopControl({
    paymentsSuspended: overview.payments_suspended,
    busy,
    localEnableBlockers,
  });
  const connectorState: ConnectorState = connector
    ? connector.phase
    : "other_wallet";
  const phone = phoneLinkState({
    statusLoaded: companion.statusLoaded,
    belongsToAnotherWallet: companion.belongsToAnotherWallet,
    enabled: companion.enabled,
    pairingActive: companion.pairingActive,
  });
  const alerts = overviewAlerts({
    paymentsSuspended: overview.payments_suspended,
    clearStopBlocked: localEnableBlockers.length > 0,
    clearStopReason: stopControl.reason,
    phone,
    hasAuthorizedPhone: companion.hasAuthorizedPhone,
    phoneAddressReady: companion.addressReady,
    pairingBlocked: pairingBlockers.length > 0,
    connector: connectorState,
    node: nodeAlertState({
      nodeStatus: overview.node_status as NodeState,
      stale: overview.stale,
    }),
  });

  /**
   * The controls the one-line strip can press itself. A row whose control is
   * not in here still renders its line; its detail names where the control is.
   * No row ever renders a button that does nothing.
   *
   * The two phone controls run the panel's own handler, read from the ref at
   * click time rather than captured at render time, so the strip can never
   * press a stale closure over an old Wi-Fi address.
   */
  const alertHandlers: Partial<Record<DesktopControlId, () => void>> = {
    enable_payments_locally: stopControl.disabled ? undefined : onEnable,
    refresh: () => void onRefresh(),
    start_connector: onStartConnector,
    clear_failed_connector: onStopConnector,
    lock_and_switch_wallet: onLockAndSwitch,
    turn_on_phone_connection: companion.canTurnOn
      ? () => companionActions.current.turnOn?.()
      : undefined,
    pair_a_phone: companion.canStartPairing
      ? () => companionActions.current.startPairing?.()
      : undefined,
  };

  const order = overviewBlockOrder({
    paymentsSuspended: overview.payments_suspended,
    phone,
    connector: connectorState,
  });

  const block = (id: OverviewBlockId) => {
    switch (id) {
      case "alerts":
        return (
          <OverviewAlerts
            key={id}
            alerts={alerts}
            handlers={alertHandlers}
            busy={busy}
          />
        );
      case "metrics":
        return (
          <div className="agent-metrics" key={id}>
            <Metric label="Available" value={formatUnits(overview.available_units)} />
            <Metric label="Reserved" value={formatUnits(overview.reserved_units)} />
            <Metric label="Spent today" value={formatUnits(overview.spent_today_units)} />
            <Metric label="Spent this month" value={formatUnits(overview.spent_this_month_units)} />
          </div>
        );
      case "phone":
        return (
          <MobileCompanionPanel
            key={id}
            walletId={overview.wallet_id}
            busy={busy}
            run={run}
            onInfo={onInfo}
            pairingBlockers={pairingBlockers}
            onSnapshot={onCompanionSnapshot}
            actionsRef={companionActions}
            onLockAndSwitch={onLockAndSwitch}
          />
        );
      case "connector":
        return (
          <ConnectorPanel
            key={id}
            connector={connector}
            pairingActivation={props.pairingActivation}
            pendingPairing={props.pendingPairing}
            busy={busy}
            onStart={onStartConnector}
            onStop={onStopConnector}
            onActivatePairing={props.onActivatePairing}
            onForgetPairingCode={props.onForgetPairingCode}
            onCheckPairing={props.onCheckPairing}
            onApprovePairing={props.onApprovePairing}
            onRejectPairing={props.onRejectPairing}
            onLockAndSwitch={onLockAndSwitch}
          />
        );
      case "payment_control":
        return (
          <PaymentControlPanel
            key={id}
            paymentsSuspended={overview.payments_suspended}
            stopControl={stopControl}
            localEnableBlockers={localEnableBlockers}
            onEnable={onEnable}
            onEmergencyStop={onEmergencyStop}
          />
        );
      case "node_health":
        return (
          <NodeHealthPanel key={id} overview={overview} paymentBlockers={paymentBlockers} />
        );
      case "payment_blockers":
        return <PaymentBlockersPanel key={id} paymentBlockers={paymentBlockers} />;
      case "authorization":
        return (
          <section className="agent-panel" key={id}>
            <h2>Authorization and approvals</h2>
            <div className="agent-stats-row">
              <span>Authorized agents <strong>{overview.authorized_agents}</strong></span>
              <span>Pending approvals <strong>{overview.pending_approvals}</strong></span>
            </div>
          </section>
        );
    }
  };

  return (
    <>
      <div className="agent-page-head">
        <div>
          <span className="agent-eyebrow">Manual approval only</span>
          <h1>AI Agent Wallet</h1>
          <p>{overview.address}</p>
        </div>
        <div className="agent-control-row">
          {/* Funding this wallet means sending HAC to this address, and there
              was no way to get the address off the screen. */}
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard
                ?.writeText(overview.address)
                .then(() => onInfo("The Agent Wallet address was copied."))
                .catch(() => undefined);
            }}
          >
            {DESKTOP_CONTROLS.copy_address}
          </button>
          <button type="button" onClick={() => void onRefresh()} disabled={busy}>
            {DESKTOP_CONTROLS.refresh}
          </button>
        </div>
      </div>
      <div className="agent-boundary-banner">
        <span className="agent-boundary-icon" aria-hidden>!</span>
        <p><strong>Separate wallet and permission domain.</strong> The AI agent cannot access your My Wallet private key.</p>
      </div>
      {order.map((id) => block(id))}
    </>
  );
}

/**
 * The short lines at the top of Overview.
 *
 * At rest this renders nothing at all. When it renders, every line is one
 * sentence, the explanation is behind "Why?", and at most one button carries
 * the primary weight.
 */
function OverviewAlerts({
  alerts,
  handlers,
  busy,
}: {
  alerts: OverviewAlert[];
  handlers: Partial<Record<DesktopControlId, () => void>>;
  busy: boolean;
}) {
  if (alerts.length === 0) return null;
  return (
    <section className="agent-alert-strip" aria-label="Needs your attention">
      {alerts.map((alert) => {
        const handler = alert.action ? handlers[alert.action.control] : undefined;
        return (
          <div
            className={`agent-alert-row ${alert.tone}`}
            key={alert.id}
            role={alert.tone === "warning" ? "alert" : "status"}
          >
            <span className="agent-alert-status">{alert.status}</span>
            <details className="agent-alert-why">
              <summary>Why?</summary>
              <p>{alert.detail}</p>
            </details>
            {alert.action && handler && (
              <button
                type="button"
                className={alert.primary ? "agent-primary-action" : ""}
                disabled={busy}
                onClick={handler}
              >
                {alert.action.label}
              </button>
            )}
          </div>
        );
      })}
    </section>
  );
}

/**
 * The Local Pilot health rows.
 *
 * Three rows answer the question an owner actually has at rest. The other
 * fifteen are reference data and are one click away, unchanged.
 */
function NodeHealthPanel({
  overview,
  paymentBlockers,
}: {
  overview: AgentWalletOverview;
  paymentBlockers: AgentWalletWriteReadiness[];
}) {
  const node = overview.node;
  return (
    <section className="agent-panel" aria-label="Testnet pilot health">
      <h2>Local Pilot health</h2>
      <dl className="agent-detail-grid">
        <div><dt>Network</dt><dd>{node?.network_kind ?? "Identity unavailable"}</dd></div>
        <div><dt>Node identity</dt><dd>{overview.node_status === "verified" ? "Verified" : "Failed closed"}</dd></div>
        <div><dt>Agent payments</dt><dd>{paymentBlockers.length === 0 ? "Ready" : "Blocked"}</dd></div>
        <div><dt>Mobile companion</dt><dd>{overview.mobile_witness_ready ? "Read-only rollback witness paired" : "Read-only rollback witness required"}</dd></div>
      </dl>
      <details className="agent-advanced-details">
        <summary>Node details</summary>
        <dl className="agent-detail-grid">
          <div><dt>Profile</dt><dd>{node?.node_profile_id ?? HPAY_LOCAL_PILOT.profileId}</dd></div>
          <div><dt>Node URL</dt><dd>{overview.node_url ?? "Unavailable"}</dd></div>
          <div><dt>Node version</dt><dd>{node ? `${node.node_name} ${node.node_version}` : "Unavailable"}</dd></div>
          <div><dt>Chain ID</dt><dd>{node?.chain_id ?? "Unavailable"}</dd></div>
          <div><dt>Mainnet</dt><dd>{node ? String(node.mainnet) : "Unavailable"}</dd></div>
          <div><dt>Current height</dt><dd>{node?.current_height ?? "Unavailable"}</dd></div>
          <div><dt>Block 1</dt><dd>{overview.block_one_fingerprint ?? "Unavailable"}</dd></div>
          <div><dt>Network instance</dt><dd>{node?.network_instance_id ?? "Unavailable"}</dd></div>
          <div><dt>Transaction-ready</dt><dd>{node?.transaction_ready ? "Yes" : "No"}</dd></div>
          <div><dt>Signing device</dt><dd>This desktop</dd></div>
          <div><dt>Approval device</dt><dd>This desktop</dd></div>
          <div><dt>Rollback witness</dt><dd>{overview.mobile_witness_synchronized ? "Synchronized" : overview.mobile_witness_ready ? "Out of sync" : "Not initialized"}</dd></div>
          <div><dt>Latest anchor</dt><dd>{overview.latest_anchor_sequence || "None"}</dd></div>
          <div><dt>Unresolved signed</dt><dd>{overview.unresolved_signed_operations}</dd></div>
        </dl>
      </details>
      {!overview.mainnet_spending_ready && (
        <div className="agent-warning">
          Legacy mainnet Agent Wallet detected. Do not fund this address.
          Spending is blocked and this release has no verified Agent Wallet
          backup or recovery path.
        </div>
      )}
      <details className="agent-advanced-details">
        <summary>What this release supports</summary>
        <p>
          Available now: HAC on L1 with desktop approval and a paired mobile
          read-only rollback witness. HACD, BTC, HIP-20, providers and Agent
          Fast Pay remain unavailable until their security paths are implemented
          and verified.
        </p>
      </details>
    </section>
  );
}

/** Why the agent cannot pay. One line at rest, the full list one click away. */
function PaymentBlockersPanel({
  paymentBlockers,
}: {
  paymentBlockers: AgentWalletWriteReadiness[];
}) {
  return (
    <section className="agent-panel" aria-label="Payment readiness blockers">
      <h2>Payment readiness blockers</h2>
      {paymentBlockers.length === 0 ? (
        <Status ok text="Agent payments: ready" />
      ) : (
        <>
          <Status
            ok={false}
            text={`Agent payments: blocked, ${paymentBlockers.length} ${
              paymentBlockers.length === 1 ? "reason" : "reasons"
            }`}
          />
          <details className="agent-advanced-details">
            <summary>What is blocking a payment</summary>
            <ul>
              {paymentBlockers.map((blocker) => (
                <li key={blocker}>{WRITE_BLOCKER_LABELS[blocker]}</li>
              ))}
            </ul>
          </details>
        </>
      )}
    </section>
  );
}

/**
 * The emergency stop and the one control that clears it.
 *
 * The sentence stating that the stop cannot reverse an already-submitted
 * transaction stays visible beside the button. It is a before-the-fact warning
 * and must never move behind a disclosure.
 */
function PaymentControlPanel({
  paymentsSuspended,
  stopControl,
  localEnableBlockers,
  onEnable,
  onEmergencyStop,
}: {
  paymentsSuspended: boolean;
  stopControl: ReturnType<typeof emergencyStopControl>;
  localEnableBlockers: AgentWalletWriteReadiness[];
  onEnable: () => void;
  onEmergencyStop: () => void;
}) {
  return (
    <section className="agent-panel">
      <h2>Payment control</h2>
      <div className="agent-control-row">
        <Status
          ok={!paymentsSuspended}
          text={paymentsSuspended ? "Payments disabled" : "Payments enabled"}
        />
        {stopControl.action === "enable" ? (
          <button
            type="button"
            className="agent-primary-action"
            onClick={onEnable}
            disabled={stopControl.disabled}
            title={stopControl.reason}
          >
            Enable locally
          </button>
        ) : (
          <button
            type="button"
            className="agent-danger"
            onClick={onEmergencyStop}
            disabled={stopControl.disabled}
            title={stopControl.reason}
          >
            Disable All Agent Payments
          </button>
        )}
      </div>
      {stopControl.action === "enable" && localEnableBlockers.length > 0 && (
        <p className="agent-warning" role="status">{stopControl.reason}</p>
      )}
      <p>{EMERGENCY_STOP_WARNING}</p>
      <details className="agent-advanced-details">
        <summary>What does this do?</summary>
        <p>
          Enabling payments never enables automatic approval. Each exact L1
          transaction still requires a user decision. Disabling also stops
          phones connecting and stops new phones being paired, and does not
          affect My Wallet.
        </p>
      </details>
    </section>
  );
}

function ConnectorPanel({
  connector,
  pairingActivation,
  pendingPairing,
  busy,
  onStart,
  onStop,
  onActivatePairing,
  onForgetPairingCode,
  onCheckPairing,
  onApprovePairing,
  onRejectPairing,
  onLockAndSwitch,
}: {
  connector: AgentConnectorStatus | null;
  pairingActivation: PairingActivation | null;
  pendingPairing: PendingPairing | null;
  busy: boolean;
  onStart: () => void;
  onStop: () => void;
  onActivatePairing: () => void;
  onForgetPairingCode: () => void;
  onCheckPairing: () => void;
  onApprovePairing: () => void;
  onRejectPairing: () => void;
  onLockAndSwitch: () => void;
}) {
  if (!connector) {
    return (
      <section className="agent-panel">
        <h2>Local Agent connector</h2>
        <div className="agent-warning" role="status">
          <p>
            The running connector belongs to another Agent Wallet. This wallet
            cannot manage it.
          </p>
          {/* The old sentence said "Open that wallet to manage it" and no
              wallet picker exists in the unlocked UI. Locking returns to the
              unlock screen, which has one. */}
          <button type="button" disabled={busy} onClick={onLockAndSwitch}>
            {DESKTOP_CONTROLS.lock_and_switch_wallet}
          </button>
        </div>
      </section>
    );
  }
  const running = connector.phase === "running";
  const failed = connector.phase === "failed";
  const canStop = running || failed || connector.phase === "stopping";
  return (
    <section className="agent-panel">
      <h2>Local Agent connector</h2>
      <div className="agent-control-row">
        {/* "Connector running" and "Connector stopped" are the internal phase
            names. They say nothing about what is or is not working. */}
        <Status ok={running} text={connectorStatusText(connector.phase)} />
        {canStop ? (
          <button type="button" onClick={onStop} disabled={busy}>
            {/* This calls stop and nothing else. It used to be labelled
                "Restart the AI agent connector", which it never did. */}
            {failed
              ? DESKTOP_CONTROLS.clear_failed_connector
              : DESKTOP_CONTROLS.stop_connector}
          </button>
        ) : (
          <button
            type="button"
            className="agent-primary-action"
            onClick={onStart}
            disabled={busy || connector.phase !== "stopped"}
          >
            {DESKTOP_CONTROLS.start_connector}
          </button>
        )}
      </div>
      <p className="agent-muted">
        For AI agent software on this computer. Not the phone connection.
      </p>
      {failed && (
        <p className="agent-muted" role="status">
          {DESKTOP_CONTROLS.clear_failed_connector} stops the connector.{" "}
          {DESKTOP_CONTROLS.start_connector} appears once it is stopped.
        </p>
      )}
      {!canStop && connector.phase !== "stopped" && (
        <p className="agent-muted" role="status">
          {DESKTOP_CONTROLS.start_connector} is unavailable while it is{" "}
          {connector.phase}. Wait for it to finish, then try again.
        </p>
      )}
      <details className="agent-advanced-details">
        <summary>What is the local Agent connector?</summary>
        <p>
          This is for AI agent software running on this computer. It is not the
          phone connection. If you are setting up or fixing a phone, use Pair
          your phone instead. Starting or stopping this costs nothing and moves
          no money.
        </p>
      </details>
      {connector.lastError && <div className="agent-warning">{connector.lastError}</div>}
      {running && (
        <>
          <p>
            Local endpoint: <code>{connector.endpoint ?? "Starting..."}</code>
          </p>
          {!pairingActivation ? (
            <button type="button" onClick={onActivatePairing} disabled={busy}>
              {DESKTOP_CONTROLS.pair_local_agent}
            </button>
          ) : (
            <div className="info-box">
              <strong>One-time pairing secret</strong>
              <code>{pairingActivation.pairingId}</code>
              <p>
                This secret is shown once and expires automatically. Share it
                only with the local agent process you intend to pair.
              </p>
              <div className="agent-control-row">
                <button type="button" onClick={onCheckPairing} disabled={busy}>
                  Check submitted identity
                </button>
                {/* The only escape used to be stopping the whole connector.
                    This clears the code from this desktop; there is no backend
                    cancel for a local-agent code, so the label promises only
                    what it can deliver. */}
                <button type="button" onClick={onForgetPairingCode} disabled={busy}>
                  {DESKTOP_CONTROLS.forget_local_agent_code}
                </button>
              </div>
            </div>
          )}
          {pendingPairing && (
            <div className="agent-warning">
              <strong>{pendingPairing.agentName}</strong>
              <p>Version: {pendingPairing.agentVersion}</p>
              <p>Identity: <code>{pendingPairing.identityFingerprint}</code></p>
              <p>
                Requested: {pendingPairing.requestedCapabilities.join(", ") || "No permissions"}
              </p>
              <p>
                Initial approval is read-only with zero spending limits. You
                can review any later permission change in Rules.
              </p>
              <div className="agent-control-row">
                <button
                  type="button"
                  className="agent-primary-action"
                  onClick={onApprovePairing}
                  disabled={busy}
                >
                  Approve read-only
                </button>
                <button type="button" className="agent-danger" onClick={onRejectPairing} disabled={busy}>
                  Reject
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

/**
 * What the connector badge means, in the owner's terms.
 *
 * The old badge printed the internal phase name, so "Connector stopped" was
 * read as a fault and "Connector running" as "my phone is fine". Neither is
 * what it reports: this is the AI agent connector on this computer only.
 */
function connectorStatusText(phase: AgentConnectorStatus["phase"]): string {
  if (phase === "running") return "AI agent connector is on";
  if (phase === "starting") return "AI agent connector is starting";
  if (phase === "stopping") return "AI agent connector is stopping";
  if (phase === "failed") return "AI agent connector failed to start";
  return "AI agent connector is off";
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="agent-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Status({ ok, text }: { ok: boolean; text: string }) {
  return <span className={`agent-status ${ok ? "ok" : "stopped"}`}>{text}</span>;
}

function formatUnits(raw: string | null): string {
  if (raw == null) return "Unavailable";
  try {
    const units = BigInt(raw);
    const whole = units / 1_000_000n;
    const fraction = (units % 1_000_000n)
      .toString()
      .padStart(6, "0")
      .replace(/0+$/, "");
    return `${whole}${fraction ? `.${fraction}` : ""} HAC`;
  } catch {
    return "Invalid balance";
  }
}

function shortAddress(address: string): string {
  return address.length > 18
    ? `${address.slice(0, 9)}...${address.slice(-7)}`
    : address;
}

function readableError(reason: unknown): string {
  if (reason instanceof Error) return reason.message;
  if (typeof reason === "string") return reason;
  return "Agent Wallet operation failed.";
}
