import { useCallback, useEffect, useState } from "react";
import { api, type AppUpdateInfo } from "../api";
import pkg from "../../package.json";

const WALLET_VERSION = pkg.version;

type Props = {
  onInfo?: (msg: string) => void;
  onError?: (msg: string) => void;
};

export default function AppUpdateSection({ onInfo, onError }: Props) {
  const [info, setInfo] = useState<AppUpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState(false);

  const check = useCallback(async () => {
    setChecking(true);
    try {
      const result = await api.checkAppUpdate("desktop", WALLET_VERSION);
      setInfo(result);
    } catch (e) {
      onError?.(String(e));
    } finally {
      setChecking(false);
    }
  }, [onError]);

  useEffect(() => {
    void check();
  }, [check]);

  const handleUpdate = async () => {
    if (!info?.download_url) return;
    setUpdating(true);
    try {
      const name = info.download_url.split("/").pop() ?? "hacash-wallet-update.exe";
      onInfo?.("Downloading update…");
      const path = await api.downloadAppUpdate(info.download_url, name);
      await api.installDesktopUpdate(path);
      onInfo?.("Installer started. Follow the prompts — your wallet data is kept.");
    } catch (e) {
      onError?.(String(e));
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="app-update-section">
      <h3>App update</h3>
      <p className="muted">
        Installed: <strong>v{WALLET_VERSION}</strong>
        {info ? (
          <>
            {" "}
            · Latest: <strong>{info.latest_version}</strong>
          </>
        ) : null}
      </p>
      {info?.update_available ? (
        <p className="update-available">A new version is available.</p>
      ) : (
        <p className="muted">You are on the latest release.</p>
      )}
      <div className="actions-row">
        <button type="button" disabled={checking || updating} onClick={() => void check()}>
          {checking ? "Checking…" : "Check again"}
        </button>
        {info?.update_available && info.download_url ? (
          <button type="button" className="primary" disabled={updating} onClick={() => void handleUpdate()}>
            {updating ? "Downloading…" : "Download & install"}
          </button>
        ) : null}
      </div>
      {info?.release_notes ? (
        <details className="update-notes">
          <summary>Release notes</summary>
          <pre>{info.release_notes}</pre>
        </details>
      ) : null}
    </div>
  );
}