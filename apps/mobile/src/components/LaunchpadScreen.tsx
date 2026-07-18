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
          onClose={() => setOpenedApp(null)}
          onError={() => {
            setOpenedApp(null);
            onNotify?.(copy.connectionError, "error");
          }}
        />
      ) : null}
    </div>
  );
}

function EmbeddedDappWebview({ app, closeLabel, openingLabel, onClose, onError }: {
  app: WalletDapp;
  closeLabel: string;
  openingLabel: string;
  onClose: () => void;
  onError: () => void;
}) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [ready, setReady] = useState(false);
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  useEffect(() => {
    if (!isTauri()) {
      onErrorRef.current();
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
          onErrorRef.current();
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
      } catch {
        if (webview) {
          await webview.close().catch(() => undefined);
          webview = null;
        }
        if (!cancelled) onErrorRef.current();
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
