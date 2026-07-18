import { useCallback, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api, type AppUpdateInfo } from "../api";
import { WALLET_VERSION } from "../walletVersion";
import { useLocale } from "../locale";

type Props = {
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function AppUpdateSection({ onToast }: Props) {
  const { t } = useLocale();
  const [info, setInfo] = useState<AppUpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [updatePhase, setUpdatePhase] = useState<"idle" | "downloading" | "installer">("idle");
  const [lastError, setLastError] = useState<string | null>(null);

  const check = useCallback(async () => {
    setChecking(true);
    setInfo(null);
    setDownloaded(false);
    setUpdatePhase("idle");
    setLastError(null);
    try {
      const result = await api.checkAppUpdate(WALLET_VERSION.replace(/^v/, ""));
      setInfo(result);
    } catch (error) {
      const message = String(error);
      setLastError(message);
      onToast(message, "error");
    } finally {
      setChecking(false);
    }
  }, [onToast]);

  const openBrowserDownload = async () => {
    if (!info?.release_page) return;
    try {
      await openUrl(info.release_page);
      onToast(t("update.openReleasePage"), "info");
    } catch (error) {
      onToast(String(error), "error");
    }
  };

  const handleUpdate = async () => {
    if (info?.status !== "available_trusted" || info.target_os !== "android") {
      onToast(t("update.unsupportedNote"), "error");
      return;
    }

    setUpdating(true);
    setLastError(null);
    try {
      if (!downloaded) {
        setUpdatePhase("downloading");
        onToast(t("update.downloadingVerifying"), "info");
        await api.downloadAppUpdate(info.offer_id);
        setDownloaded(true);
      }
      setUpdatePhase("installer");
      onToast(t("update.openingAndroidInstaller"), "info");
      await api.installMobileUpdate(info.offer_id);
    } catch (error) {
      const message = String(error);
      setLastError(message);
      onToast(message, "error");
    } finally {
      setUpdating(false);
      setUpdatePhase("idle");
    }
  };

  const platformLabel = info ? `${info.target_os} ${info.target_arch}` : "";
  return (
    <div className="card app-update-section">
      <h2>{t("update.title")}</h2>
      <p className="muted">
        {t("update.installed")}: <strong>{WALLET_VERSION}</strong>
        {info ? (
          <>
            {" | "}{t("update.latest")}: <strong>{info.latest_version}</strong>
          </>
        ) : null}
      </p>

      {info === null ? (
        <p className="muted">{t("update.notChecked")}</p>
      ) : info.status === "available_trusted" ? (
        <p className="update-available">{t("update.trustedAvailable", { platform: platformLabel })}</p>
      ) : info.status === "available_manual" ? (
        <p className="update-available">{t("update.manualAvailable", { platform: platformLabel })}</p>
      ) : info.status === "available_untrusted" ? (
        <p className="update-error">{t("update.untrustedAvailable", { platform: platformLabel })}</p>
      ) : (
        <p className="muted">{t("update.upToDate", { platform: platformLabel })}</p>
      )}

      {lastError ? <p className="update-error">{lastError}</p> : null}

      <div className="row-btns">
        <button type="button" disabled={checking || updating} onClick={() => void check()}>
          {checking ? t("update.checking") : info ? t("update.checkAgain") : t("update.check")}
        </button>
        {info?.status === "available_trusted" && info.target_os === "android" ? (
          <button type="button" className="primary" disabled={updating} onClick={() => void handleUpdate()}>
            {updatePhase === "downloading"
              ? t("update.downloadingVerifying")
              : updatePhase === "installer"
                ? t("update.openingAndroidInstaller")
                : downloaded
                  ? t("update.openVerifiedApk")
                  : t("update.downloadVerifyApk")}
          </button>
        ) : null}
        {info?.release_page ? (
          <button type="button" disabled={updating} onClick={() => void openBrowserDownload()}>
            {t("update.openReleasePage")}
          </button>
        ) : null}
      </div>

      {info?.status === "available_manual" ? (
        <p className="muted small">{t("update.unsupportedNote")}</p>
      ) : info?.target_os === "android" ? (
        <p className="muted small">
          {t("update.androidTrustNote")}
          {" "}
          {t("update.androidManualNote")}
        </p>
      ) : null}

      {info?.release_notes ? (
        <details className="update-notes">
          <summary>{t("update.releaseNotes")}</summary>
          <pre>{info.release_notes}</pre>
        </details>
      ) : null}
    </div>
  );
}
