import { useCallback, useEffect, useState } from "react";
import { api, type AppUpdateInfo } from "../api";
import { WALLET_VERSION } from "../walletVersion";

type Props = {
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function AppUpdateSection({ onToast }: Props) {
  const [info, setInfo] = useState<AppUpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState(false);

  const check = useCallback(async () => {
    setChecking(true);
    try {
      const result = await api.checkAppUpdate("mobile", WALLET_VERSION.replace(/^v/, ""));
      setInfo(result);
    } catch (e) {
      onToast(String(e), "error");
    } finally {
      setChecking(false);
    }
  }, [onToast]);

  useEffect(() => {
    void check();
  }, [check]);

  const handleUpdate = async () => {
    if (!info?.download_url) return;
    setUpdating(true);
    try {
      const name = info.download_url.split("/").pop() ?? "hacash-wallet-update.apk";
      onToast("Downloading update…", "info");
      const path = await api.downloadAppUpdate(info.download_url, name);
      await api.installMobileUpdate(path);
      onToast("Confirm install on the system prompt. Wallet data is kept.", "success");
    } catch (e) {
      onToast(String(e), "error");
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="card app-update-section">
      <h2>App update</h2>
      <p className="muted">
        Installed: <strong>{WALLET_VERSION}</strong>
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
      <div className="row-btns">
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