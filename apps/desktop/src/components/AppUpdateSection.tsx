import { useCallback, useState } from "react";
import { api, type AppUpdateInfo } from "../api";
import pkg from "../../package.json";
import { useLocale } from "../locale";

const WALLET_VERSION = pkg.version;

type Props = {
  onInfo?: (msg: string) => void;
  onError?: (msg: string) => void;
};

export default function AppUpdateSection({ onInfo, onError }: Props) {
  const { t } = useLocale();
  const [info, setInfo] = useState<AppUpdateInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [downloaded, setDownloaded] = useState(false);

  const check = useCallback(async () => {
    setChecking(true);
    setInfo(null);
    setDownloaded(false);
    try {
      setInfo(await api.checkAppUpdate(WALLET_VERSION));
    } catch (error) {
      onError?.(String(error));
    } finally {
      setChecking(false);
    }
  }, [onError]);

  const handleUpdate = async () => {
    if (info?.status !== "available_trusted" || info.target_os !== "windows") {
      onError?.(t("update.unsupportedNote"));
      return;
    }

    setUpdating(true);
    try {
      if (!downloaded) {
        onInfo?.(t("update.downloadingVerifying"));
        await api.downloadAppUpdate(info.offer_id);
        setDownloaded(true);
      }
      onInfo?.(t("update.openingVerifiedInstaller"));
      await api.installDesktopUpdate(info.offer_id);
    } catch (error) {
      onError?.(String(error));
    } finally {
      setUpdating(false);
    }
  };

  const releasePage = info?.release_page;
  const platformLabel = info ? `${info.target_os} ${info.target_arch}` : "";

  return (
    <div className="app-update-section">
      <h3>{t("update.title")}</h3>
      <p className="muted">
        {t("update.installed")}: <strong>v{WALLET_VERSION}</strong>
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

      <div className="actions-row">
        <button type="button" disabled={checking || updating} onClick={() => void check()}>
          {checking ? t("update.checking") : info ? t("update.checkAgain") : t("update.check")}
        </button>
        {info?.status === "available_trusted" && info.target_os === "windows" ? (
          <button type="button" className="primary" disabled={updating} onClick={() => void handleUpdate()}>
            {updating
              ? downloaded
                ? t("update.openingVerifiedInstaller")
                : t("update.downloadingVerifying")
              : downloaded
                ? t("update.openVerifiedInstaller")
                : t("update.downloadVerifyInstaller")}
          </button>
        ) : null}
        {releasePage ? (
          <button
            type="button"
            disabled={updating}
            onClick={() => {
              void import("@tauri-apps/plugin-shell")
                .then(({ open }) => open(releasePage))
                .catch((error) => onError?.(String(error)));
            }}
          >
            {t("update.openReleasePage")}
          </button>
        ) : null}
      </div>

      {info?.target_os === "linux" ? (
        <p className="muted small-note">
          {t("update.linuxManualNote")}
        </p>
      ) : info?.target_os === "windows" ? (
        <p className="muted small-note">
          {t("update.windowsTrustNote")}
        </p>
      ) : info ? (
        <p className="muted small-note">
          {t("update.unsupportedNote")}
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
