import { useCallback, useEffect, useRef, useState } from "react";
import { LogicalPosition, LogicalSize } from "@tauri-apps/api/dpi";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Webview } from "@tauri-apps/api/webview";
import { api } from "../api";
import { MONEYNEX_INJECT_SCRIPT_V2 } from "../dapp/moneynexInjectScript";

const LAUNCHPAD_URL = "https://hacd.it/launchpad";
const LAUNCHPAD_ORIGIN = "https://hacd.it";
const MOBILE_VIEWPORT_W = 390;
const LAUNCHPAD_WEBVIEW_LABEL = "launchpad";
const ACTIVITY_INTERVAL_MS = 45_000;

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

type Props = {
  pauseAutoLockDapp?: boolean;
};

export default function LaunchpadScreen({ pauseAutoLockDapp = true }: Props) {
  const shellRef = useRef<HTMLDivElement>(null);
  const webviewRef = useRef<Webview | null>(null);
  const [scale, setScale] = useState(1);
  const [frameH, setFrameH] = useState(640);
  const [useNativeWebview, setUseNativeWebview] = useState(false);
  const [connected, setConnected] = useState<string | null>(null);
  const [connectBusy, setConnectBusy] = useState(false);

  const bumpActivity = useCallback(() => {
    void api.bumpActivity().catch(() => undefined);
  }, []);

  const injectMoneyNex = useCallback(async () => {
    if (!isTauri()) return;
    try {
      await api.webviewEval(LAUNCHPAD_WEBVIEW_LABEL, MONEYNEX_INJECT_SCRIPT_V2);
    } catch {
      /* webview may still be loading */
    }
  }, []);

  const handleConnect = useCallback(async () => {
    setConnectBusy(true);
    try {
      const res = await api.dappConnect(LAUNCHPAD_ORIGIN);
      if (res.address) {
        setConnected(res.address);
        bumpActivity();
      }
    } finally {
      setConnectBusy(false);
    }
  }, [bumpActivity]);

  useEffect(() => {
    if (!pauseAutoLockDapp) return;
    bumpActivity();
    const interval = window.setInterval(bumpActivity, ACTIVITY_INTERVAL_MS);
    const onVisible = () => {
      if (!document.hidden) bumpActivity();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [bumpActivity, pauseAutoLockDapp]);

  useEffect(() => {
    const shell = shellRef.current;
    if (!shell) return;

    const update = () => {
      const w = shell.clientWidth;
      const h = shell.clientHeight;
      const nextScale = w > 0 ? w / MOBILE_VIEWPORT_W : 1;
      setScale(nextScale);
      setFrameH(h > 0 ? h / nextScale : 640);
    };

    update();
    const ro = new ResizeObserver(update);
    ro.observe(shell);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    if (!isTauri()) return;

    let cancelled = false;
    const shell = shellRef.current;
    if (!shell) return;

    const mountWebview = async () => {
      try {
        const existing = await Webview.getByLabel(LAUNCHPAD_WEBVIEW_LABEL);
        if (existing) {
          await existing.close().catch(() => undefined);
        }

        const rect = shell.getBoundingClientRect();
        const appWindow = getCurrentWindow();
        const x = Math.round(rect.left);
        const y = Math.round(rect.top);
        const width = Math.max(Math.round(rect.width), 320);
        const height = Math.max(Math.round(rect.height), 400);

        const webview = new Webview(appWindow, LAUNCHPAD_WEBVIEW_LABEL, {
          url: LAUNCHPAD_URL,
          x,
          y,
          width,
          height,
          focus: true,
          backgroundColor: { red: 0, green: 0, blue: 0, alpha: 255 },
        });

        await new Promise<void>((resolve, reject) => {
          const timeout = window.setTimeout(() => reject(new Error("launchpad webview timeout")), 12_000);
          webview.once("tauri://created", () => {
            window.clearTimeout(timeout);
            resolve();
          });
          webview.once("tauri://error", (e) => {
            window.clearTimeout(timeout);
            reject(e);
          });
        });

        if (cancelled) {
          await webview.close();
          return;
        }

        webviewRef.current = webview;
        setUseNativeWebview(true);
        await injectMoneyNex();
        window.setTimeout(() => void injectMoneyNex(), 1200);
        window.setTimeout(() => void injectMoneyNex(), 3500);

        const resize = () => {
          const r = shell.getBoundingClientRect();
          void webview.setPosition(new LogicalPosition(r.left, r.top));
          void webview.setSize(
            new LogicalSize(Math.max(r.width, 320), Math.max(r.height, 400)),
          );
        };
        const ro = new ResizeObserver(resize);
        ro.observe(shell);

        return () => {
          ro.disconnect();
        };
      } catch {
        setUseNativeWebview(false);
      }
    };

    void mountWebview();

    return () => {
      cancelled = true;
      const wv = webviewRef.current;
      webviewRef.current = null;
      if (wv) void wv.close().catch(() => undefined);
    };
  }, [injectMoneyNex]);

  useEffect(() => {
    void api.dappWallet(LAUNCHPAD_ORIGIN).then((res) => {
      if (res.address) setConnected(res.address);
    });
  }, []);

  useEffect(() => {
    if (!connected || !pauseAutoLockDapp) return;
    const heartbeat = window.setInterval(() => {
      void api.dappHeartbeat(LAUNCHPAD_ORIGIN).catch(() => undefined);
    }, 30_000);
    return () => window.clearInterval(heartbeat);
  }, [connected, pauseAutoLockDapp]);

  return (
    <div className="launchpad-wrap">
      <div className="launchpad-connect-bar">
        <div className="launchpad-connect-copy">
          <strong>HACD Launchpad</strong>
          <span>
            {connected
              ? `Connected · ${connected.slice(0, 8)}…${connected.slice(-6)}`
              : "Connect your Hacash Wallet to trade on hacd.it"}
          </span>
        </div>
        <button
          type="button"
          className="primary launchpad-connect-btn"
          disabled={connectBusy || !!connected}
          onClick={() => void handleConnect()}
        >
          {connected ? "Connected" : connectBusy ? "Connecting…" : "Connect"}
        </button>
      </div>
      <div className="launchpad-shell" ref={shellRef}>
        {!useNativeWebview && (
          <div
            className="launchpad-mobile-stage"
            style={{ transform: `scale(${scale})`, width: MOBILE_VIEWPORT_W, height: frameH }}
          >
            <iframe
              className="launchpad-frame"
              src={LAUNCHPAD_URL}
              title="HACD Launchpad"
              width={MOBILE_VIEWPORT_W}
              height={frameH}
              sandbox="allow-scripts allow-same-origin allow-popups allow-forms"
            />
          </div>
        )}
        {useNativeWebview && <div className="launchpad-webview-placeholder" aria-hidden />}
      </div>
    </div>
  );
}