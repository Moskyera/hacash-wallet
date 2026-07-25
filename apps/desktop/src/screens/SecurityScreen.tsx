import { useState } from "react";
import { useLocale } from "../locale";

type Props = {
  busy: boolean;
  onChangePassphrase: (old: string, newPass: string, confirm: string) => Promise<boolean>;
  onExportBackup: (passphrase: string) => Promise<string | null>;
};

export default function SecurityScreen({
  busy,
  onChangePassphrase,
  onExportBackup,
}: Props) {
  const { t } = useLocale();
  const [oldPassphrase, setOldPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [backupJson, setBackupJson] = useState("");

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
    </>
  );
}
