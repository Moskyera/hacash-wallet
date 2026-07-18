import { useRef, useState } from "react";
import { api } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { useLocale } from "../locale";
import { copyWithPrivacyClear } from "../privacy";

type Props = {
  watchOnly: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  clipboardSecs: number;
  onChangePassphrase: (old: string, newPass: string, confirm: string) => Promise<boolean>;
  onExportBackup: (passphrase: string) => Promise<string | null>;
  onError: (msg: string) => void;
  onInfo: (msg: string) => void;
  clearMessages: () => void;
};

export default function SecurityScreen({
  watchOnly,
  busy,
  setBusy,
  clipboardSecs,
  onChangePassphrase,
  onExportBackup,
  onError,
  onInfo,
  clearMessages,
}: Props) {
  const { t } = useLocale();
  const [oldPassphrase, setOldPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [backupJson, setBackupJson] = useState("");
  const [privateKeyPass, setPrivateKeyPass] = useState("");
  const [privateKey, setPrivateKey] = useState<string | null>(null);
  const privateKeyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  return (
    <>
      <hr className="divider" />

      <h3>{t("security.changePassphrase")}</h3>
      <label>{t("security.currentPassphrase")}</label>
      <input
        type="password"
        value={oldPassphrase}
        onChange={(e) => setOldPassphrase(e.target.value)}
      />
      <label>{t("security.newPassphrase")}</label>
      <input
        type="password"
        value={newPassphrase}
        onChange={(e) => setNewPassphrase(e.target.value)}
      />
      <label>{t("security.confirmNewPassphrase")}</label>
      <input
        type="password"
        value={confirmPassphrase}
        onChange={(e) => setConfirmPassphrase(e.target.value)}
      />
      <button
        disabled={
          busy || !oldPassphrase || !newPassphrase || newPassphrase !== confirmPassphrase
        }
        onClick={() =>
          void onChangePassphrase(oldPassphrase, newPassphrase, confirmPassphrase).then(
            (ok) => {
              if (ok) {
                setOldPassphrase("");
                setNewPassphrase("");
                setConfirmPassphrase("");
              }
            },
          )
        }
      >
        {t("security.changePassphrase")}
      </button>

      <hr className="divider" />

      <h3>{t("security.exportBackup")}</h3>
      <p className="muted">{t("security.exportBackupHint")}</p>
      <label>{t("security.exportPassphrase")}</label>
      <input
        type="password"
        value={exportPassphrase}
        onChange={(e) => setExportPassphrase(e.target.value)}
      />
      <button
        disabled={busy || !exportPassphrase}
        onClick={() =>
          void onExportBackup(exportPassphrase).then((json) => {
            if (json) {
              setBackupJson(json);
              setExportPassphrase("");
            }
          })
        }
      >
        {t("security.exportBackup")}
      </button>
      {backupJson && (
        <textarea
          className="textarea mono"
          readOnly
          value={backupJson}
          rows={8}
          aria-label={t("security.exportedBackupJson")}
        />
      )}

      <hr className="divider" />

      <h3>{t("security.privateKey")}</h3>
      <p className="muted">{t("security.privateKeyDesktopHint")}</p>
      <label>{t("security.passphrase")}</label>
      <input
        type="password"
        value={privateKeyPass}
        onChange={(e) => setPrivateKeyPass(e.target.value)}
      />
      <button
        type="button"
        disabled={busy || watchOnly || !privateKeyPass}
        onClick={() => {
          setBusy(true);
          clearMessages();
          void api
            .exportPrivateKey(privateKeyPass)
            .then((hex) => {
              setPrivateKey(hex);
              setPrivateKeyPass("");
              onInfo(t("security.privateKeyRevealed"));
              if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
              privateKeyTimer.current = setTimeout(() => setPrivateKey(null), 60_000);
            })
            .catch((e) => onError(formatInvokeError(e)))
            .finally(() => setBusy(false));
        }}
      >
        {t("security.revealPrivateKey")}
      </button>
      {privateKey && (
        <>
          <p className="mono small" style={{ wordBreak: "break-all", marginTop: "0.75rem" }}>
            {privateKey}
          </p>
          <div className="actions-row" style={{ marginTop: "0.5rem" }}>
            <button
              type="button"
              onClick={() =>
                void copyWithPrivacyClear(privateKey, clipboardSecs).then(() =>
                  onInfo(t("security.privateKeyCopied")),
                )
              }
            >
              {t("common.copy")}
            </button>
            <button
              type="button"
              onClick={() => {
                setPrivateKey(null);
                if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
              }}
            >
              {t("common.hide")}
            </button>
          </div>
        </>
      )}
    </>
  );
}
