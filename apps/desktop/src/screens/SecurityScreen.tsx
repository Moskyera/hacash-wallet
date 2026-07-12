import { useRef, useState } from "react";
import { api } from "../api";
import { formatInvokeError } from "../formatInvokeError";
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

      <h3>Change passphrase</h3>
      <label>Current passphrase</label>
      <input
        type="password"
        value={oldPassphrase}
        onChange={(e) => setOldPassphrase(e.target.value)}
      />
      <label>New passphrase</label>
      <input
        type="password"
        value={newPassphrase}
        onChange={(e) => setNewPassphrase(e.target.value)}
      />
      <label>Confirm new passphrase</label>
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
        Change passphrase
      </button>

      <hr className="divider" />

      <h3>Export backup</h3>
      <p className="muted">
        Export an encrypted JSON backup. Restore via Welcome → Restore backup (same passphrase).
        Delete the backup file after a one-time restore.
      </p>
      <label>Passphrase to decrypt vault for export</label>
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
        Export backup
      </button>
      {backupJson && (
        <textarea
          className="textarea mono"
          readOnly
          value={backupJson}
          rows={8}
          aria-label="Exported backup JSON"
        />
      )}

      <hr className="divider" />

      <h3>Private key</h3>
      <p className="muted">
        Advanced: view your wallet private key. Anyone with this key controls your funds.
        Never share it.
      </p>
      <label>Passphrase</label>
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
              onInfo("Private key revealed. It will hide in 60s.");
              if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
              privateKeyTimer.current = setTimeout(() => setPrivateKey(null), 60_000);
            })
            .catch((e) => onError(formatInvokeError(e)))
            .finally(() => setBusy(false));
        }}
      >
        Reveal private key
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
                  onInfo("Private key copied."),
                )
              }
            >
              Copy
            </button>
            <button
              type="button"
              onClick={() => {
                setPrivateKey(null);
                if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
              }}
            >
              Hide
            </button>
          </div>
        </>
      )}
    </>
  );
}