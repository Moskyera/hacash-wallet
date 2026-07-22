import { useCallback, useEffect, useRef, useState } from "react";

import "./dappApps.css";
import {
  WALLET_DAPP_CATALOG,
  canOpenDapp,
  shortWalletAddress,
  type DappConnectionState,
  type WalletDapp,
  type WalletDappId,
} from "./dappApps";

export type DappConnectionApi = {
  connect: (origin: string) => Promise<{ address?: string; err?: string }>;
  disconnect: (origin: string) => Promise<{ ok: boolean; disconnected: boolean }>;
  wallet: (origin: string) => Promise<{ address?: string; err?: string }>;
  heartbeat: (origin: string) => Promise<{ ok?: boolean; err?: string }>;
};

type ConnectionOptions = {
  beforeConnect?: () => void | Promise<void>;
  afterDisconnect?: () => void | Promise<void>;
  onConnected?: (app: WalletDapp) => void;
  onDisconnected?: (app: WalletDapp) => void;
  onError?: (cause: unknown) => void;
};

const HEARTBEAT_MS = 5_000;
const RECONCILE_MS = 1_500;

export function useDappConnection(
  app: WalletDapp | null,
  api: DappConnectionApi,
  options: ConnectionOptions = {},
) {
  const [state, setState] = useState<DappConnectionState>({ status: "disconnected" });
  const generation = useRef(0);
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const refresh = useCallback(async () => {
    const current = ++generation.current;
    if (!app) {
      setState({ status: "disconnected" });
      return;
    }
    setState({ status: "checking" });
    try {
      const result = await api.wallet(app.origin);
      if (current !== generation.current) return;
      setState(
        result.address
          ? { status: "connected", address: result.address }
          : { status: "disconnected" },
      );
    } catch (cause) {
      if (current !== generation.current) return;
      setState({ status: "error" });
      optionsRef.current.onError?.(cause);
    }
  }, [api, app]);

  useEffect(() => {
    void refresh();
    return () => {
      generation.current += 1;
    };
  }, [refresh]);

  const connect = useCallback(async () => {
    if (!app || state.status === "connecting" || state.status === "disconnecting") return;
    const current = ++generation.current;
    setState({ status: "connecting" });
    try {
      await optionsRef.current.beforeConnect?.();
      const result = await api.connect(app.origin);
      if (!result.address) throw new Error(result.err || "The dApp connection was not authorized");
      if (current !== generation.current) return;
      setState({ status: "connected", address: result.address });
      optionsRef.current.onConnected?.(app);
    } catch (cause) {
      if (current !== generation.current) return;
      setState({ status: "error" });
      optionsRef.current.onError?.(cause);
    }
  }, [api, app, state.status]);

  const disconnect = useCallback(async () => {
    if (!app || state.status !== "connected") return;
    const address = state.address;
    const current = ++generation.current;
    setState({ status: "disconnecting", address });
    try {
      await api.disconnect(app.origin);
      await optionsRef.current.afterDisconnect?.();
      if (current !== generation.current) return;
      setState({ status: "disconnected" });
      optionsRef.current.onDisconnected?.(app);
    } catch (cause) {
      if (current !== generation.current) return;
      setState({ status: "error" });
      optionsRef.current.onError?.(cause);
    }
  }, [api, app, state]);

  useEffect(() => {
    if (!app || state.status !== "connected") return;
    let cancelled = false;
    let inFlight = false;
    const heartbeat = async () => {
      if (cancelled || inFlight) return;
      inFlight = true;
      try {
        const result = await api.heartbeat(app.origin);
        if (!cancelled && result.ok === false) setState({ status: "disconnected" });
      } catch {
        // A transient IPC/network error must not invent a disconnected state.
      } finally {
        inFlight = false;
      }
    };
    const id = window.setInterval(() => void heartbeat(), HEARTBEAT_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [api, app, state.status]);

  useEffect(() => {
    if (!app || (state.status !== "disconnected" && state.status !== "error")) return;
    let cancelled = false;
    let inFlight = false;
    const reconcile = async () => {
      if (cancelled || inFlight) return;
      inFlight = true;
      try {
        const result = await api.wallet(app.origin);
        if (cancelled || !result.address) return;
        setState({ status: "connected", address: result.address });
        optionsRef.current.onConnected?.(app);
      } catch {
        // The explicit status remains truthful across a transient IPC error.
      } finally {
        inFlight = false;
      }
    };
    const id = window.setInterval(() => void reconcile(), RECONCILE_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [api, app, state.status]);

  return { state, connect, disconnect, refresh };
}

export type DappAppSelectorCopy = {
  appsTitle: string;
  appsSubtitle: string;
  select: string;
  selected: string;
  checking: string;
  connected: string;
  disconnected: string;
  connect: string;
  connecting: string;
  disconnect: string;
  disconnecting: string;
  open: string;
  address: string;
  connectionError: string;
  watchOnly: string;
  hacdLaunchpadDescription: string;
};

export function translatedDappAppSelectorCopy(t: (key: string) => string): DappAppSelectorCopy {
  return {
    appsTitle: t("dapp.appsTitle"),
    appsSubtitle: t("dapp.appsSubtitle"),
    select: t("dapp.select"),
    selected: t("dapp.selected"),
    checking: t("dapp.checking"),
    connected: t("dapp.connected"),
    disconnected: t("dapp.disconnected"),
    connect: t("dapp.connect"),
    connecting: t("dapp.connecting"),
    disconnect: t("dapp.disconnect"),
    disconnecting: t("dapp.disconnecting"),
    open: t("dapp.open"),
    address: t("dapp.address"),
    connectionError: t("dapp.connectionError"),
    watchOnly: t("dapp.watchOnly"),
    hacdLaunchpadDescription: t("dapp.hacdLaunchpadDescription"),
  };
}

export type DappApprovalCopy = {
  kindConnect: string;
  kindSign: string;
  kindTransfer: string;
  hintConnect: string;
  hintSign: string;
  hintTransfer: string;
  hintDefault: string;
  from: string;
  showDetails: string;
  hideDetails: string;
  decline: string;
  accept: string;
  approve: string;
  working: string;
  checkingApproval: string;
  approvalFootnote: string;
  mobileWarning: string;
  requestApproved: string;
  requestDeclined: string;
};

export function translatedDappApprovalCopy(t: (key: string) => string): DappApprovalCopy {
  return {
    kindConnect: t("dapp.kindConnect"),
    kindSign: t("dapp.kindSign"),
    kindTransfer: t("dapp.kindTransfer"),
    hintConnect: t("dapp.hintConnect"),
    hintSign: t("dapp.hintSign"),
    hintTransfer: t("dapp.hintTransfer"),
    hintDefault: t("dapp.hintDefault"),
    from: t("dapp.from"),
    showDetails: t("dapp.showDetails"),
    hideDetails: t("dapp.hideDetails"),
    decline: t("dapp.decline"),
    accept: t("dapp.accept"),
    approve: t("dapp.approve"),
    working: t("dapp.working"),
    checkingApproval: t("dapp.checkingApproval"),
    approvalFootnote: t("dapp.approvalFootnote"),
    mobileWarning: t("dapp.mobileWarning"),
    requestApproved: t("dapp.requestApproved"),
    requestDeclined: t("dapp.requestDeclined"),
  };
}

export type DappApprovalKindCopy = { label: string; hint: string };

export function dappApprovalKindCopy(
  kind: string,
  copy: DappApprovalCopy,
): DappApprovalKindCopy {
  switch (kind) {
    case "connect":
      return { label: copy.kindConnect, hint: copy.hintConnect };
    case "sign":
      return { label: copy.kindSign, hint: copy.hintSign };
    case "transfer":
      return { label: copy.kindTransfer, hint: copy.hintTransfer };
    default:
      return { label: copy.approve, hint: copy.hintDefault };
  }
}

export function DappAppSelector({
  selectedId,
  connection,
  copy,
  onSelect,
  onConnect,
  onDisconnect,
  onOpen,
  apps = WALLET_DAPP_CATALOG,
  disabled = false,
  watchOnly = false,
  compact = false,
}: {
  selectedId: WalletDappId | null;
  connection: DappConnectionState;
  copy: DappAppSelectorCopy;
  onSelect: (id: WalletDappId) => void;
  onConnect: () => void;
  onDisconnect: () => void;
  onOpen: (app: WalletDapp) => void;
  apps?: readonly WalletDapp[];
  disabled?: boolean;
  watchOnly?: boolean;
  compact?: boolean;
}) {
  const selected = apps.find((app) => app.id === selectedId) ?? null;
  const connected = connection.status === "connected" || connection.status === "disconnecting";
  const openEnabled = canOpenDapp(connection);
  const working = connection.status === "checking" || connection.status === "connecting" || connection.status === "disconnecting";
  const statusText =
    connection.status === "checking"
      ? copy.checking
      : connection.status === "connecting"
        ? copy.connecting
        : connection.status === "disconnecting"
          ? copy.disconnecting
          : connection.status === "connected"
            ? copy.connected
            : connection.status === "error"
              ? copy.connectionError
              : copy.disconnected;

  return (
    <section className={`dapp-app-selector${compact ? " dapp-app-selector-compact" : ""}`}>
      <header className="dapp-app-selector-head">
        <h2>{copy.appsTitle}</h2>
        <p>{copy.appsSubtitle}</p>
      </header>
      <div className="dapp-app-list" role="listbox" aria-label={copy.appsTitle}>
        {apps.map((app) => {
          const isSelected = app.id === selectedId;
          return (
            <button
              key={app.id}
              type="button"
              className={`dapp-app-option${isSelected ? " is-selected" : ""}`}
              role="option"
              aria-selected={isSelected}
              disabled={disabled || working || (connected && !isSelected)}
              onClick={() => onSelect(app.id)}
            >
              <span className="dapp-app-mark" aria-hidden>H</span>
              <span className="dapp-app-option-copy">
                <strong>{app.name}</strong>
                <small>{copy.hacdLaunchpadDescription}</small>
              </span>
              <span className="dapp-app-select-label">{isSelected ? copy.selected : copy.select}</span>
            </button>
          );
        })}
      </div>

      {selected ? (
        <div className="dapp-app-connection" aria-live="polite">
          <div className="dapp-app-connection-copy">
            <strong>{selected.name}</strong>
            <span className={`dapp-app-status dapp-app-status-${connection.status}`}>{statusText}</span>
            {connection.status === "connected" || connection.status === "disconnecting" ? (
              <span title={connection.address}>
                {copy.address}: {shortWalletAddress(connection.address)}
              </span>
            ) : null}
            {watchOnly ? <span>{copy.watchOnly}</span> : null}
          </div>
          <div className="dapp-app-actions">
            {connected ? (
              <button type="button" disabled={disabled || working} onClick={onDisconnect}>
                {connection.status === "disconnecting" ? copy.disconnecting : copy.disconnect}
              </button>
            ) : (
              <button
                type="button"
                className="primary"
                disabled={disabled || working || watchOnly}
                onClick={onConnect}
              >
                {connection.status === "connecting" ? copy.connecting : copy.connect}
              </button>
            )}
            <button
              type="button"
              disabled={disabled || !openEnabled}
              onClick={() => {
                if (openEnabled) onOpen(selected);
              }}
            >
              {copy.open}
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
