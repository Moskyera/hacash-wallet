import { useCallback, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api, type AppUpdateInfo } from "../api";
import { WALLET_VERSION } from "../walletVersion";

type Props = {
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function AppUpdateSection({ onToast }: Props) {
  const [info, setInfo] = useState<AppUpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updatePhase, setUpdatePhase] = useState<"idle" | "downloading" | "installer">("idle");
  const [lastError, setLastError] = useState<string | null>(null);

  const check = useCallback(async () => {
    setChecking(true);
    setLastError(null);
    try {
      const result = await api.checkAppUpdate("mobile", WALLET_VERSION.replace(/^v/, ""));
      setInfo(result);
    } catch (e) {
      const msg = String(e);
      setLastError(msg);
      onToast(msg, "error");
    } finally {
      setChecking(false);
    }
  }, [onToast]);

  const openBrowserDownload = async () => {
    const url = info?.download_url ?? info?.release_page;
    if (!url) return;
    try {
      await openUrl(url);
      onToast("Download opened in browser. Install the APK when ready.", "info");
    } catch (e) {
      onToast(String(e), "error");
    }
  };

  const handleUpdate = async () => {
    if (!info?.download_url) return;
    setUpdating(true);
    setUpdatePhase("downloading");
    setLastError(null);
    try {
      const name = info.download_url.split("/").pop() ?? "hacash-wallet-update.apk";
      onToast("Downloading update…", "info");
      const path = await api.downloadAppUpdate(info.download_url, name);
      setUpdatePhase("installer");
      onToast("Opening system installer…", "info");
      await api.installMobileUpdate(path);
      onToast(
        "Choose a package installer if prompted, then tap Install. This app stays on the current version until you confirm.",
        "success",
      );
    } catch (e) {
      const msg = String(e);
      setLastError(msg);
      onToast(msg, "error");
      if (info.download_url) {
        onToast("Try “Open in browser” if install did not start.", "info");
      }
    } finally {
      setUpdating(false);
      setUpdatePhase("idle");
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
      {lastError ? <p className="update-error">{lastError}</p> : null}
      <div className="row-btns">
        <button type="button" disabled={checking || updating} onClick={() => void check()}>
          {checking ? "Checking…" : "Check again"}
        </button>
        {info?.update_available && info.download_url ? (
          <>
            <button type="button" className="primary" disabled={updating} onClick={() => void handleUpdate()}>
              {updatePhase === "downloading"
                ? "Downloading…"
                : updatePhase === "installer"
                  ? "Opening installer…"
                  : "Download & install"}
            </button>
            <button type="button" disabled={updating} onClick={() => void openBrowserDownload()}>
              Open in browser
            </button>
          </>
        ) : null}
      </div>
      <p className="muted small">
        The app may go to the background while Android shows the install screen — that is normal. If install asks
        for permission, enable &quot;Install unknown apps&quot; for Hacash Wallet, then try again.
      </p>
      {info?.release_notes ? (
        <details className="update-notes">
          <summary>Release notes</summary>
          <pre>{info.release_notes}</pre>
        </details>
      ) : null}
    </div>
  );
}