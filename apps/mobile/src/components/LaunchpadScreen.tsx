import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LogicalPosition, LogicalSize } from "@tauri-apps/api/dpi";
import { Webview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  DappAppSelector,
  MONEYNEX_INITIAL_INJECTION_DELAYS_MS,
  MONEYNEX_REINJECT_INTERVAL_MS,
  WALLET_DAPP_CATALOG,
  createMoneyNexInjectScript,
  translatedDappAppSelectorCopy,
  useDappConnection,
  walletDappById,
  type DappConnectionApi,
  type WalletDapp,
  type WalletDappId,
} from "@hacash/wallet-ui";

import { api } from "../api";
import { useLocale } from "../locale";
import { WALLET_VERSION } from "../walletVersion";

const LAUNCHPAD_WEBVIEW_LABEL = "launchpad";
const MONEYNEX_INJECT_SCRIPT = createMoneyNexInjectScript(WALLET_VERSION);
const CONNECTION_API: DappConnectionApi = {
  connect: api.dappConnect,
  disconnect: api.dappDisconnect,
  wallet: api.dappWallet,
  heartbeat: api.dappHeartbeat,
};

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

type Props = {
  pauseAutoLockDapp?: boolean;
  watchOnly?: boolean;
  onNotify?: (message: string, kind: "error" | "info" | "success") => void;
};

export default function LaunchpadScreen({ watchOnly = false, onNotify }: Props) {
  const { t } = useLocale();
  const copy = useMemo(() => translatedDappAppSelectorCopy(t), [t]);
  const [selectedId, setSelectedId] = useState<WalletDappId | null>(null);
  const [openedApp, setOpenedApp] = useState<WalletDapp | null>(null);
  const selectedApp = walletDappById(selectedId);
  const connection = useDappConnection(selectedApp, CONNECTION_API, {
    onConnected: () => onNotify?.(copy.connected, "success"),
    onDisconnected: () => {
      setOpenedApp(null);
      onNotify?.(copy.disconnected, "info");
    },
    onError: () => onNotify?.(copy.connectionError, "error"),
  });

  const selectApp = useCallback((id: WalletDappId) => {
    setSelectedId(id);
    setOpenedApp(null);
  }, []);

  useEffect(() => {
    if (connection.state.status !== "connected") setOpenedApp(null);
  }, [connection.state.status]);

  return (
    <div className="launchpad-wrap">
      <DappAppSelector
        apps={WALLET_DAPP_CATALOG}
        selectedId={selectedId}
        connection={connection.state}
        copy={copy}
        onSelect={selectApp}
        onConnect={() => void connection.connect()}
        onDisconnect={() => void connection.disconnect()}
        onOpen={setOpenedApp}
        watchOnly={watchOnly}
      />
      {openedApp ? (
        <EmbeddedDappWebview
          app={openedApp}
          closeLabel={t("dapp.close")}
          openingLabel={t("dapp.opening")}
          connectionErrorLabel={copy.connectionError}
          onClose={() => setOpenedApp(null)}
          onError={(reason) => {
            setOpenedApp(null);
            onNotify?.(reason, "error");
          }}
        />
      ) : null}
    </div>
  );
}

/**
 * Does this platform have the command an embedded dApp panel is built on?
 *
 * `new Webview(...)` invokes `plugin:webview|create_webview`, and tauri 2.11.3
 * registers that command as `#[cfg(desktop)] desktop_commands::create_webview`
 * inside a `#[cfg(desktop)] mod desktop_commands`. On Android it is not compiled
 * in at all, so the call rejects with a command-not-found error no matter what
 * the ACL says - and the mobile default capability does grant
 * `core:webview:allow-create-webview`, so the ACL genuinely is not the obstacle.
 *
 * Detected from the error rather than from a user-agent string, because the
 * error is what actually happened. A user-agent test would be a guess about the
 * platform; this is the platform answering.
 */
function embeddedDappSupportRefusal(reason: unknown): string | null {
  const text = reason instanceof Error ? reason.message : String(reason ?? "");
  const notFound =
    /not found|not allowed|unknown command|create_webview|UnstableFeatureNotSupported/i.test(
      text,
    );
  if (!notFound) return null;
  return (
    "This phone cannot open a dApp inside the wallet. The embedded panel is built " +
    "on a webview command that only exists in the desktop build, so there is " +
    "nothing to fix in your connection or your network. Open this dApp on the " +
    "HPAY desktop wallet, or in your phone's browser."
  );
}

function EmbeddedDappWebview({ app, closeLabel, openingLabel, connectionErrorLabel, onClose, onError }: {
  app: WalletDapp;
  closeLabel: string;
  openingLabel: string;
  connectionErrorLabel: string;
  onClose: () => void;
  onError: (reason: string) => void;
}) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [ready, setReady] = useState(false);
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const connectionErrorRef = useRef(connectionErrorLabel);
  connectionErrorRef.current = connectionErrorLabel;

  useEffect(() => {
    if (!isTauri()) {
      onErrorRef.current(
        "This page is not running inside the wallet app, so it cannot open a dApp panel.",
      );
      return;
    }
    const host = hostRef.current;
    if (!host) return;
    let cancelled = false;
    let webview: Webview | null = null;
    let observer: ResizeObserver | null = null;
    const timers: number[] = [];
    let reinjectInterval: number | null = null;
    let injectionInFlight = false;
    let injectionFailed = false;

    const position = () => {
      if (!webview || !host.isConnected) return;
      const rect = host.getBoundingClientRect();
      void webview.setPosition(new LogicalPosition(rect.left, rect.top));
      void webview.setSize(
        new LogicalSize(Math.max(rect.width, 320), Math.max(rect.height, 420)),
      );
    };

    const mount = async () => {
      try {
        const existing = await Webview.getByLabel(LAUNCHPAD_WEBVIEW_LABEL);
        if (existing) await existing.close().catch(() => undefined);
        if (cancelled) return;
        const rect = host.getBoundingClientRect();
        const child = new Webview(getCurrentWindow(), LAUNCHPAD_WEBVIEW_LABEL, {
          url: app.launchUrl,
          x: rect.left,
          y: rect.top,
          width: Math.max(rect.width, 320),
          height: Math.max(rect.height, 420),
          focus: true,
          backgroundColor: { red: 0, green: 0, blue: 0, alpha: 255 },
        });
        webview = child;
        await new Promise<void>((resolve, reject) => {
          const timeout = window.setTimeout(() => reject(new Error("dApp webview timeout")), 12_000);
          child.once("tauri://created", () => {
            window.clearTimeout(timeout);
            resolve();
          });
          child.once("tauri://error", (event) => {
            window.clearTimeout(timeout);
            reject(event);
          });
        });
        if (cancelled) {
          await child.close().catch(() => undefined);
          webview = null;
          return;
        }
        setReady(true);
        observer = new ResizeObserver(position);
        observer.observe(host);
        window.addEventListener("scroll", position, true);
        const failClosed = async () => {
          if (cancelled || injectionFailed) return;
          injectionFailed = true;
          timers.forEach(window.clearTimeout);
          if (reinjectInterval !== null) {
            window.clearInterval(reinjectInterval);
            reinjectInterval = null;
          }
          observer?.disconnect();
          observer = null;
          window.removeEventListener("scroll", position, true);
          setReady(false);
          const failedWebview = webview;
          webview = null;
          const closePromise = failedWebview?.close().catch(() => undefined);
          // The dApp mounted and then its bridge failed. That IS a connection
          // problem, unlike the mount failure below, so the wording stays.
          onErrorRef.current(connectionErrorRef.current);
          await closePromise;
        };
        const inject = async () => {
          if (cancelled || injectionFailed || injectionInFlight) return;
          injectionInFlight = true;
          try {
            await api.webviewEval(
              LAUNCHPAD_WEBVIEW_LABEL,
              app.origin,
              MONEYNEX_INJECT_SCRIPT,
            );
          } catch {
            await failClosed();
          } finally {
            injectionInFlight = false;
          }
        };
        for (const delay of MONEYNEX_INITIAL_INJECTION_DELAYS_MS) {
          timers.push(window.setTimeout(() => void inject(), delay));
        }
        reinjectInterval = window.setInterval(
          () => void inject(),
          MONEYNEX_REINJECT_INTERVAL_MS,
        );
      } catch (reason) {
        // Was `catch {` with no binding, which discarded the only evidence of
        // what went wrong and then reported a fixed "connection error". That
        // sent a person to check their Wi-Fi for a command that does not exist
        // on their platform.
        if (webview) {
          await webview.close().catch(() => undefined);
          webview = null;
        }
        if (!cancelled) {
          onErrorRef.current(
            embeddedDappSupportRefusal(reason) ??
              `${connectionErrorRef.current} ${
                reason instanceof Error ? reason.message : String(reason)
              }`,
          );
        }
      }
    };

    void mount();
    return () => {
      cancelled = true;
      observer?.disconnect();
      window.removeEventListener("scroll", position, true);
      timers.forEach(window.clearTimeout);
      if (reinjectInterval !== null) window.clearInterval(reinjectInterval);
      if (webview) void webview.close().catch(() => undefined);
    };
  }, [app]);

  return (
    <section className="dapp-embedded-panel">
      <header>
        <strong>{app.name}</strong>
        <button type="button" onClick={onClose}>{closeLabel}</button>
      </header>
      <div ref={hostRef} className="dapp-embedded-host">
        {!ready ? <p>{openingLabel}</p> : null}
      </div>
    </section>
  );
}
