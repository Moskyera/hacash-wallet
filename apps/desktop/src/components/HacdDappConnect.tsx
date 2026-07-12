import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-shell";
import { api } from "../api";

const LAUNCHPAD_ORIGIN = "https://hacd.it";
const LAUNCHPAD_URL = "https://hacd.it/launchpad";
const BRIDGE_EXT_PATH = "hacd-browser-bridge";
const KEEPALIVE_MS = 45_000;

type Props = {
  watchOnly?: boolean;
  pauseAutoLockDapp?: boolean;
  onNotify?: (msg: string, kind: "info" | "error") => void;
};

export default function HacdDappConnect({
  watchOnly,
  pauseAutoLockDapp = true,
  onNotify,
}: Props) {
  const [connected, setConnected] = useState<string | null>(null);
  const [connectBusy, setConnectBusy] = useState(false);
  const [bridgeRunning, setBridgeRunning] = useState(false);

  const refreshBridge = useCallback(async () => {
    try {
      const st = await api.dappBridgeStatus();
      setBridgeRunning(!!st.running);
    } catch {
      setBridgeRunning(false);
    }
  }, []);

  useEffect(() => {
    void refreshBridge();
    void api.dappWallet(LAUNCHPAD_ORIGIN).then((res) => {
      if (res.address) setConnected(res.address);
    });
  }, [refreshBridge]);

  useEffect(() => {
    if (!connected || !pauseAutoLockDapp) return;
    void api.bumpActivity().catch(() => undefined);
    const id = window.setInterval(() => {
      void api.bumpActivity().catch(() => undefined);
    }, KEEPALIVE_MS);
    return () => window.clearInterval(id);
  }, [connected, pauseAutoLockDapp]);

  const handleConnect = useCallback(async () => {
    if (watchOnly) return;
    setConnectBusy(true);
    try {
      await api.dappBridgeStart();
      const res = await api.dappConnect(LAUNCHPAD_ORIGIN);
      if (res.address) {
        setConnected(res.address);
        await refreshBridge();
        onNotify?.("Connected to HACD Launchpad.", "info");
      } else if (res.err) {
        onNotify?.(res.err, "error");
      }
    } catch (e) {
      onNotify?.(String(e), "error");
    } finally {
      setConnectBusy(false);
    }
  }, [onNotify, refreshBridge, watchOnly]);

  const handleOpenLaunchpad = useCallback(async () => {
    try {
      await open(LAUNCHPAD_URL);
    } catch (e) {
      onNotify?.(String(e), "error");
    }
  }, [onNotify]);

  const handleInstallBridgeHint = useCallback(() => {
    onNotify?.(
      `Chrome/Edge → Extensions → Developer mode → Load unpacked → select apps/desktop/${BRIDGE_EXT_PATH} in the wallet repo.`,
      "info",
    );
  }, [onNotify]);

  if (watchOnly) {
    return (
      <div className="hacd-dapp-connect">
        <p className="muted small-note">
          HACD Launchpad trading requires a signing wallet. Watch-only cannot connect.
        </p>
        <button type="button" className="ghost" onClick={() => void handleOpenLaunchpad()}>
          Open Launchpad in browser
        </button>
      </div>
    );
  }

  return (
    <div className="hacd-dapp-connect">
      <div className="hacd-dapp-connect-bar">
        <div className="hacd-dapp-connect-copy">
          <strong>HACD Launchpad</strong>
          <span>
            {connected
              ? `Connected · ${connected.slice(0, 10)}…${connected.slice(-8)}`
              : "Connect wallet, then open hacd.it in your browser"}
          </span>
          <span className="muted small-note">
            Browser bridge: {bridgeRunning ? "running on 127.0.0.1:9477" : "start Connect to enable"}
          </span>
        </div>
        <div className="hacd-dapp-connect-actions">
          <button
            type="button"
            className="primary"
            disabled={connectBusy || !!connected}
            onClick={() => void handleConnect()}
          >
            {connected ? "Connected" : connectBusy ? "Connecting…" : "Connect"}
          </button>
          <button type="button" onClick={() => void handleOpenLaunchpad()}>
            Open Launchpad
          </button>
        </div>
      </div>
      <p className="muted small-note">
        One-time setup:{" "}
        <button type="button" className="linkish" onClick={handleInstallBridgeHint}>
          Install browser bridge extension
        </button>{" "}
        (Chrome/Edge).
        {pauseAutoLockDapp
          ? " Auto-lock pauses while connected and hacd.it is open (Privacy setting)."
          : " Auto-lock during HACD is off — enable it in Privacy if the wallet locks on hacd.it."}
      </p>
    </div>
  );
}