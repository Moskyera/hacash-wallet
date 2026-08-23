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
  AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT,
  HPAY_LOCAL_PILOT,
  HPAY_MAINNET,
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
import {
  EMERGENCY_STOP_STOPS_LISTENERS,
  EMERGENCY_STOP_WARNING,
} from "./irreversibleActions";
import {
  CLEAR_STOP_CANCELS_PENDING_REQUESTS,
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
  /**
   * Bumped whenever the phone panel must re-read. Its own refresh is a read and
   * is idempotent, so this triggers a status read and nothing else.
   */
  const [companionRefreshToken, setCompanionRefreshToken] = useState(0);
  const companionActions = useRef<CompanionActions>({
    turnOn: null,
    turnOff: null,
    startPairing: null,
    retryAutomaticSetup: null,
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

  /**
   * Everything the Overview shows, re-read together.
   *
   * Refresh used to read only `agent_wallet_overview`, so the connector phase
   * and the phone connection status were never re-read at all. That is why the
   * connector could sit on "starting" for good beside a sentence saying "wait
   * for it to finish, then try again": nothing ever asked again. It is also
   * what left the connector and phone panels asserting they were on after an
   * emergency stop had torn both listeners down.
   *
   * Three reads and one state bump. Nothing here starts, stops or changes
   * anything.
   */
  const refreshAll = useCallback(async () => {
    setCompanionRefreshToken((token) => token + 1);
    await Promise.all([refreshOverview(), refreshRuntime()]);
  }, [refreshOverview, refreshRuntime]);

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
      // The runtime read belongs here too: without it a connector that finished
      // starting, failed, or was stopped by something else never showed up.
      void refreshAll().catch(() => undefined);
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [overview?.unlocked, refreshAll]);

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
          <p>The AI Agent Wallet backend is not enabled in this build.</p>
          <p>Use a reviewed HPAY Agent Wallet build to access this space.</p>
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
                input.mainnetPilotAcknowledgement,
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
        <PilotBanner overview={overview} />
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
          onError={setError}
          onRefresh={refreshAll}
          paymentBlockers={paymentBlockers}
          localEnableBlockers={localEnableBlockers}
          pairingBlockers={pairingBlockers}
          companion={companion}
          companionActions={companionActions}
          companionRefreshToken={companionRefreshToken}
          onCompanionSnapshot={setCompanion}
          onOpenPage={setPage}
          onLockAndSwitch={() => void lockAgentWallet()}
          onEmergencyStop={() =>
            run(async () => {
              await agentWalletApi.emergencyStop(overview.wallet_id);
              // agent_wallet_emergency_stop also tears down the AI agent
              // connector and the phone listener, and cancels any pairing that
              // was on screen. Re-reading only the overview left both panels
              // reporting that they were still on.
              setPairingActivation(null);
              setPendingPairing(null);
              setInfo(
                "All Agent Wallet payments are disabled. The AI agent connector and the phone connection on this desktop were stopped too, and any pairing in progress was cancelled. Paired phones and agents stay paired.",
              );
              await refreshAll();
            })
          }
          onEnable={() =>
            run(async () => {
              await agentWalletApi.enablePayments(overview.wallet_id);
              // enable_agent_payments_locally cancels every pending
              // pre-signing operation on the wallet, for every agent. Saying so
              // afterwards is not enough on its own; PaymentControlPanel and
              // the Security page both say it before the press.
              setInfo(
                "Agent payments are enabled. Every payment still requires manual approval. Every payment request that was waiting for your decision was cancelled, so each agent has to ask again.",
              );
              await refreshAll();
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
                  allow_unlisted_recipient_with_approval: false,
                  approval_mode: "desktop_manual",
                  policy_epoch: 1,
                },
              );
              setPairingActivation(null);
              setPendingPairing(null);
              setInfo(
                "The local agent is paired read-only. Spending remains disabled in Rules. Every payment request that was waiting for your decision, on every other agent, was cancelled and has to be asked again.",
              );
              await refreshAll();
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

function PilotBanner({ overview }: { overview?: AgentWalletOverview }) {
  if (overview?.network_mode === "mainnet") {
    return (
      <section className="agent-pilot-banner" role="status" aria-label="Agent Wallet network safety">
        <strong>AI AGENT WALLET</strong>
        <span>HACASH MAINNET</span>
        <span>TRUSTED BOUNDED FAST PAY PILOT</span>
        <span>0% WALLET FEE</span>
        <code>{overview.node?.network_instance_id ?? HPAY_MAINNET.blockOne}</code>
      </section>
    );
  }
  return (
    <section className="agent-pilot-banner" role="status" aria-label="Agent Wallet network safety">
      <strong>AI AGENT WALLET</strong>
      <span>{overview ? HPAY_LOCAL_PILOT.label : "NETWORK VERIFIED AFTER UNLOCK"}</span>
      <span>{overview ? "PRIVATE DEVELOPMENT NETWORK" : "PAYMENTS FAIL CLOSED"}</span>
      <span>{overview ? "NO MAINNET FUNDS" : "SEPARATE ENCRYPTED VAULT"}</span>
      {overview && <code>{HPAY_LOCAL_PILOT.networkInstance}</code>}
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
    networkMode: "mainnet" | "testnet";
    nodeUrl: string;
    blockOneFingerprint: string | null;
    mainnetPilotAcknowledgement: string | null;
  }) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [networkMode, setNetworkMode] = useState<"mainnet" | "testnet">("testnet");
  const [mainnetNodeUrl, setMainnetNodeUrl] = useState("");
  const [mainnetAcknowledged, setMainnetAcknowledged] = useState(false);
  const isMainnet = networkMode === "mainnet";
  const localError = useMemo(() => {
    if (passphrase && passphrase.length < 15) return "Use at least 15 characters.";
    if (confirmation && passphrase !== confirmation) return "Passphrases do not match.";
    if (isMainnet && mainnetNodeUrl && !mainnetNodeUrl.startsWith("https://")) {
      return "Agent mainnet requires an HTTPS HPAY-compatible full node.";
    }
    return "";
  }, [passphrase, confirmation, isMainnet, mainnetNodeUrl]);
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
        My Wallet and AI Agent Wallet use different addresses, private keys,
        encrypted vaults and Fast Pay channels. The agent cannot access My Wallet.
      </div>
      <details className="agent-advanced-details">
        <summary>What this wallet can and cannot do</summary>
        <ul>
          <li>Choose Local Pilot for testing or the reviewed bounded mainnet pilot.</li>
          {/* This said "Every payment requires manual desktop approval." In a
              Testnet Pilot build the desktop cannot complete an approval at
              all, so that read as a description of a working flow. */}
          <li>
            Every payment requires an explicit decision, and no payment is ever
            approved automatically.
          </li>
          <li>
            Every payment is bound to one exact payee, amount, Hub, channel and
            approval. The wallet rechecks them before signing and submission.
          </li>
          <li>Agents never receive a private key or raw signing access.</li>
          <li>Agent Fast Pay has no HPAY wallet fee.</li>
          <li>
            Network kind: {HPAY_LOCAL_PILOT.networkKind}. Profile:{" "}
            {HPAY_LOCAL_PILOT.profileId}. This private chain is not the official
            Hacash testnet.
          </li>
        </ul>
      </details>
      {(error || localError) && <div className="alert">{error || localError}</div>}
      {/* Before the passphrase is chosen, not after the fact on another screen.
          The only place this release stated it was inside Local Pilot health,
          which an owner reaches long after creating the wallet. */}
      <div className="agent-warning">
        The encrypted backup and its passphrase can recreate a live spending
        wallet. Store them separately and securely. Never run two restored
        copies of the same Agent Wallet at the same time.
      </div>
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
          <select
            value={networkMode}
            onChange={(event) => {
              setNetworkMode(event.target.value as "mainnet" | "testnet");
              setMainnetAcknowledged(false);
            }}
          >
            <option value="testnet">{HPAY_LOCAL_PILOT.label}</option>
            <option value="mainnet">Hacash Mainnet bounded pilot</option>
          </select>
        </label>
        {isMainnet ? (
          <label>
            HPAY-compatible mainnet full node (HTTPS)
            <input
              value={mainnetNodeUrl}
              placeholder="https://node.example"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setMainnetNodeUrl(event.target.value.trim())}
            />
          </label>
        ) : (
          <label>
            Local Pilot node API
            <input value={HPAY_LOCAL_PILOT.nodeUrl} readOnly />
          </label>
        )}
        <label>
          Local Pilot block 1 fingerprint
          <input
            value={isMainnet ? HPAY_MAINNET.blockOne : HPAY_LOCAL_PILOT.blockOne}
            inputMode="text"
            autoComplete="off"
            spellCheck={false}
            maxLength={64}
            readOnly
          />
        </label>
      </details>
      {isMainnet && (
        <div className="agent-warning">
          <strong>Mainnet trusted bounded pilot</strong>
          <p>
            Fast Pay depends on the selected Hub. Until unilateral L1 exit is
            independently verified, no Hub may exceed 1 HAC per payment,
            10 HAC per channel and 100 HAC aggregate TVL. Those are the
            ceilings this build refuses to cross, not the limits you get. A
            Hub declares its own and they are often far lower. What your Hub
            declares is what applies to you.
          </p>
          <label>
            <input
              type="checkbox"
              checked={mainnetAcknowledged}
              onChange={(event) => setMainnetAcknowledged(event.target.checked)}
            />
            {AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT}
          </label>
        </div>
      )}
      <button
        type="button"
        className="agent-primary"
        disabled={
          busy ||
          passphrase.length < 15 ||
          passphrase !== confirmation ||
          (isMainnet && (!mainnetAcknowledged || !mainnetNodeUrl.startsWith("https://")))
        }
        onClick={() =>
          onCreate({
            passphrase,
            networkMode,
            nodeUrl: isMainnet ? mainnetNodeUrl : HPAY_LOCAL_PILOT.nodeUrl,
            blockOneFingerprint: isMainnet ? null : HPAY_LOCAL_PILOT.blockOne,
            mainnetPilotAcknowledgement: isMainnet
              ? AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT
              : null,
          })
        }
      >
        {busy
          ? "Creating encrypted vault..."
          : isMainnet
            ? "Create bounded mainnet Agent Wallet"
            : "Create Local Pilot Agent Wallet"}
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
  /** Reports a failure that never reaches `run`, such as a refused clipboard. */
  onError: (message: string) => void;
  onRefresh: () => Promise<void>;
  /** Gates decision 1 only: making a payment. */
  paymentBlockers: AgentWalletWriteReadiness[];
  /** Gates decision 2 only: clearing the emergency stop from this desktop. */
  localEnableBlockers: AgentWalletWriteReadiness[];
  /** Gates decision 3 only: pairing a phone. */
  pairingBlockers: AgentWalletWriteReadiness[];
  companion: CompanionSnapshot;
  companionActions: React.MutableRefObject<CompanionActions>;
  /** Bumped by the page-head Refresh and after an emergency stop. */
  companionRefreshToken: number;
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
    onError,
    onRefresh,
    paymentBlockers,
    localEnableBlockers,
    pairingBlockers,
    companion,
    companionActions,
    companionRefreshToken,
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
    listenerFailed: companion.listenerFailed,
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
    // Against a dead listener slot this is the only press that can succeed:
    // start is refused while the slot is held.
    turn_off_phone_connection: companion.canTurnOff
      ? () => companionActions.current.turnOff?.()
      : undefined,
    pair_a_phone: companion.canStartPairing
      ? () => companionActions.current.startPairing?.()
      : undefined,
    // Without a private Wi-Fi address neither phone control can run, so this
    // is the control that state depends on. It was named by the strip but had
    // to be scrolled to; now the strip presses the panel's own handler.
    retry_automatic_setup: companion.canRetryAutomaticSetup
      ? () => companionActions.current.retryAutomaticSetup?.()
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
            localEnableBlockers={localEnableBlockers}
            refreshToken={companionRefreshToken}
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
          {/* The second route. Copy address can fail, and this is selectable
              text, so the address the owner has to fund is never only behind a
              button. */}
          <p className="agent-exact-address">{overview.address}</p>
        </div>
        <div className="agent-control-row">
          {/* Funding this wallet means sending HAC to this address, and there
              was no way to get the address off the screen.

              The optional chain used to short-circuit the whole expression when
              navigator.clipboard was absent, and the trailing catch discarded a
              rejected write, so the press produced no line, no error, nothing
              at all. Both now report. */}
          <button
            type="button"
            onClick={() => {
              const clipboard = navigator.clipboard;
              if (!clipboard) {
                onError(
                  "This desktop did not offer a clipboard, so nothing was copied. The full address is shown above this row and can be selected and copied by hand.",
                );
                return;
              }
              void clipboard
                .writeText(overview.address)
                .then(() => onInfo("The Agent Wallet address was copied."))
                .catch((reason) =>
                  onError(
                    `The address could not be copied to the clipboard, so nothing was copied. The full address is shown above this row and can be selected and copied by hand. ${readableError(reason)}`,
                  ),
                );
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
      <AgentFastPayChannelPanel
        overview={overview}
        busy={busy}
        run={run}
        onInfo={onInfo}
        onRefresh={onRefresh}
      />
      {order.map((id) => block(id))}
    </>
  );
}

function AgentFastPayChannelPanel({
  overview,
  busy,
  run,
  onInfo,
  onRefresh,
}: {
  overview: AgentWalletOverview;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
  onRefresh: () => Promise<void>;
}) {
  const [hubUrl, setHubUrl] = useState("");
  const [deposit, setDeposit] = useState("1");
  const setup = overview.l2_channel_setup;
  const close = overview.l2_channel_close;
  const binding = overview.l2_binding;
  const active = Boolean(binding && !binding.closed);

  const finish = async (message: string) => {
    onInfo(message);
    await onRefresh();
  };

  return (
    <section className="agent-panel">
      <span className="agent-eyebrow">Owner controlled</span>
      <h2>Agent Fast Pay channel</h2>
      <p>
        This channel belongs only to the Agent Wallet. It never uses the Personal Wallet channel
        and it adds no HPAY wallet fee.
      </p>

      {!binding && !setup && (
        <>
          <label className="agent-field">
            <span>Fast Pay Hub</span>
            <input
              value={hubUrl}
              onChange={(event) => setHubUrl(event.target.value)}
              placeholder="https://your-fast-pay-hub.example"
              disabled={busy}
            />
          </label>
          <label className="agent-field">
            <span>Agent channel deposit (HAC)</span>
            <input
              value={deposit}
              onChange={(event) => setDeposit(event.target.value)}
              inputMode="decimal"
              disabled={busy}
            />
          </label>
          <button
            type="button"
            className="agent-primary"
            disabled={busy || !hubUrl.trim() || !deposit.trim()}
            onClick={() =>
              void run(async () => {
                await agentWalletApi.prepareFastPayChannel(
                  overview.wallet_id,
                  hubUrl.trim(),
                  deposit.trim(),
                );
                await finish("Review the exact Agent channel deposit and network fee.");
              })
            }
          >
            Review channel setup
          </button>
        </>
      )}

      {setup && !binding && (
        <>
          <div className="agent-stats-row">
            <span>Deposit <strong>{formatUnits(setup.deposit_units)}</strong></span>
            <span>Network fee <strong>{formatUnits(setup.network_fee_units)}</strong></span>
            <span>Wallet fee <strong>{formatUnits(setup.wallet_fee_units)}</strong></span>
            <span>Status <strong>{setup.phase.replace(/_/g, " ")}</strong></span>
          </div>
          {setup.fee_estimate_degraded ? (
            <p className="agent-warning" role="status">
              {setup.fee_estimate_degraded}
            </p>
          ) : null}
          <p className="agent-exact-address">{setup.channel_id}</p>
          <div className="agent-control-row">
            {setup.phase === "prepared" ? (
              <button
                type="button"
                className="agent-primary"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    await agentWalletApi.confirmFastPayChannelSetup(
                      overview.wallet_id,
                      setup.operation_id,
                      setup.review_commitment,
                    );
                    await finish("Agent Fast Pay channel setup advanced safely.");
                  })
                }
              >
                Confirm exact setup
              </button>
            ) : (
              <button
                type="button"
                className="agent-primary"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    await agentWalletApi.recoverFastPayChannelSetup(overview.wallet_id);
                    await finish("Agent channel recovery checked the exact saved operation.");
                  })
                }
              >
                Check or recover setup
              </button>
            )}
          </div>
        </>
      )}

      {binding && (
        <div className="agent-stats-row">
          <span>Channel <strong>{binding.channel_id}</strong></span>
          <span>Deposit <strong>{formatUnits(binding.deposit_units)}</strong></span>
          <span>Status <strong>{active ? "ready" : "closed"}</strong></span>
        </div>
      )}

      {active && !close && (
        <button
          type="button"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              await agentWalletApi.prepareFastPayChannelClose(overview.wallet_id);
              await finish("Review the final signed balance and close network fee.");
            })
          }
        >
          Review channel close
        </button>
      )}

      {close && (
        <>
          <div className="agent-stats-row">
            <span>Current Agent share <strong>{formatUnits(close.original_agent_units)}</strong></span>
            <span>Final Agent share <strong>{formatUnits(close.final_agent_units)}</strong></span>
            <span>Network fee <strong>{formatUnits(close.network_fee_units)}</strong></span>
            <span>Wallet fee <strong>{formatUnits(close.wallet_fee_units)}</strong></span>
            <span>Status <strong>{close.phase.replace(/_/g, " ")}</strong></span>
          </div>
          {close.fee_estimate_degraded ? (
            <p className="agent-warning" role="status">
              {close.fee_estimate_degraded}
            </p>
          ) : null}
          {close.phase === "prepared" ? (
            <button
              type="button"
              className="agent-primary"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await agentWalletApi.confirmFastPayChannelClose(
                    overview.wallet_id,
                    close.operation_id,
                    close.review_commitment,
                  );
                  await finish("Agent channel close advanced safely.");
                })
              }
            >
              Confirm exact close
            </button>
          ) : close.phase !== "confirmed" ? (
            <button
              type="button"
              className="agent-primary"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await agentWalletApi.recoverFastPayChannelClose(overview.wallet_id);
                  await finish("Agent close recovery checked the exact saved signature and ID.");
                })
              }
            >
              Check or recover close
            </button>
          ) : (
            <p>The Agent Fast Pay channel is closed. Its signed history remains available.</p>
          )}
        </>
      )}
    </section>
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
          <div><dt>Witness rotation</dt><dd>{overview.witness_rotation_phase?.replace(/_/g, " ") ?? "stable"}</dd></div>
          {/* Fetched all along and rendered nowhere, so the real reason a node
              check failed was discarded and the strip guessed at it instead. */}
          <div className="wide"><dt>Last node check</dt><dd>{overview.node_error ?? "No failure reported"}</dd></div>
        </dl>
      </details>
      {!overview.mainnet_spending_ready && (
        <div className="agent-warning">
          Legacy mainnet Agent Wallet detected. Do not fund this address.
          Spending is blocked. A backup of this wallet's state can be made under
          Backup and restore, and restoring one rewinds the record of what has
          been spent - read the warning there before you rely on it.
        </div>
      )}
      <details className="agent-advanced-details">
        <summary>What this release supports</summary>
        <p>
          {/* This claimed "HAC on L1 with desktop approval" was available. The
              desktop approval command refuses unconditionally in a pilot
              build, and the Desktop only approval mode this desktop writes
              also refuses the phone, so nothing could be approved. */}
          Available now: proposing, reviewing and rejecting HAC payments on L1,
          with a paired mobile read-only rollback witness. Completing a payment
          is not available: this pilot build has no device that can approve one.
          HACD, BTC, HIP-20, providers and Agent Fast Pay remain unavailable
          until their security paths are implemented and verified.
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
      {/* Before the press and never behind a disclosure. Enabling was described
          everywhere as a control that changes nothing but the flag; it cancels
          every pending payment request on the wallet. */}
      {stopControl.action === "enable" && (
        <p className="agent-warning" role="status">
          {CLEAR_STOP_CANCELS_PENDING_REQUESTS}
        </p>
      )}
      {stopControl.action === "disable" && (
        <p className="agent-warning" role="status">
          {EMERGENCY_STOP_STOPS_LISTENERS}
        </p>
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
          {connector.phase}. Nothing on this screen changes that. Choose{" "}
          {DESKTOP_CONTROLS.refresh} at the top of this page to ask again: it
          re-reads the connector, the phone connection and the node, and costs
          nothing. This state also re-reads itself every fifteen seconds.
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
              {/* Before the press. `record_pairing_approval`
                  (crates/agent-wallet-core/src/service/connector.rs) cancels
                  every pre-signing operation on the wallet, scope None, before
                  it records the new agent. Nothing here said so. */}
              <p className="agent-warning" role="status">
                Approving also cancels every payment request that is waiting for
                your decision, on every other agent on this wallet. Those
                requests are gone and each agent has to ask again. Reject
                changes nothing.
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
