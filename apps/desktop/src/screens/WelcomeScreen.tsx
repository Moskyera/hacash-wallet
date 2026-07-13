import { useRef, useState } from "react";
import WalletLogo from "../components/WalletLogo";
import { api } from "../api";
import { readBackupJsonFile } from "../utils/readBackupFile";
import { isValidImportSeed, type WelcomeTab } from "./types";

type Props = {
  busy: boolean;
  onCreate: (passphrase: string) => void;
  onImport: (seed: string, passphrase: string) => void;
  onImportBackup: (json: string, passphrase: string, deleteSource?: string | null) => void;
  onWatchOnly: (address: string) => void;
};

export default function WelcomeScreen({
  busy,
  onCreate,
  onImport,
  onImportBackup,
  onWatchOnly,
}: Props) {
  const [welcomeTab, setWelcomeTab] = useState<WelcomeTab>("create");
  const [passphrase, setPassphrase] = useState("");
  const [importSeed, setImportSeed] = useState("");
  const [importPassphrase, setImportPassphrase] = useState("");
  const [watchAddress, setWatchAddress] = useState("");
  const [backupJson, setBackupJson] = useState("");
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [backupDeleteSource, setBackupDeleteSource] = useState<string | undefined>();
  const [backupPreview, setBackupPreview] = useState<string | null>(null);
  const [backupFileName, setBackupFileName] = useState<string | null>(null);
  const backupInputRef = useRef<HTMLInputElement>(null);

  const loadBackupFile = async (file: File) => {
    const payload = await readBackupJsonFile(file);
    setBackupJson(payload.json);
    setBackupDeleteSource(payload.deleteSource);
    setBackupFileName(file.name);
    setBackupPreview(null);
    try {
      const addr = await api.previewBackup(payload.json);
      setBackupPreview(addr);
    } catch {
      setBackupPreview(null);
    }
  };

  return (
    <div className="auth-layout auth-layout-welcome">
      <div className="auth-welcome">
        <div className="auth-hero">
          <WalletLogo size="lg" />
          <h1>Your modern Hacash wallet</h1>
          <p className="muted">
            Encrypted keys on device. Fast Pay when available, otherwise on-chain.
          </p>
        </div>

        <div className="display-toggle welcome-tabs">
          <button
            type="button"
            className={welcomeTab === "create" ? "selected" : ""}
            onClick={() => setWelcomeTab("create")}
          >
            Create
          </button>
          <button
            type="button"
            className={welcomeTab === "import" ? "selected" : ""}
            onClick={() => setWelcomeTab("import")}
          >
            Import
          </button>
          <button
            type="button"
            className={welcomeTab === "backup" ? "selected" : ""}
            onClick={() => setWelcomeTab("backup")}
          >
            Restore
          </button>
          <button
            type="button"
            className={welcomeTab === "watch" ? "selected" : ""}
            onClick={() => setWelcomeTab("watch")}
          >
            Watch
          </button>
        </div>

        <div className="auth-form auth-form-centered">
          {welcomeTab === "create" && (
            <>
              <p className="muted small-note">
                A unique wallet is generated on this device. Back up your secret in Security after
                creating.
              </p>
              <label>Encryption passphrase</label>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Min 8 characters (12+ recommended)"
              />
              <button
                className="primary auth-submit"
                disabled={busy || passphrase.length < 8}
                onClick={() => onCreate(passphrase)}
              >
                Create wallet
              </button>
            </>
          )}

          {welcomeTab === "watch" && (
            <>
              <label>Hacash address to monitor</label>
              <input
                value={watchAddress}
                onChange={(e) => setWatchAddress(e.target.value)}
                placeholder="1YourAddress..."
              />
              <p className="muted small-note">
                Watch-only mode. No private key on this device — cannot send or sign.
              </p>
              <button
                className="primary auth-submit"
                disabled={busy || watchAddress.trim().length < 10}
                onClick={() => onWatchOnly(watchAddress)}
              >
                Add watch-only wallet
              </button>
            </>
          )}

          {welcomeTab === "import" && (
            <>
              <label>Secret hex or legacy passphrase seed</label>
              <textarea
                className="textarea"
                value={importSeed}
                onChange={(e) => setImportSeed(e.target.value)}
                placeholder="64-char hex secret, or legacy passphrase"
                rows={3}
              />
              <label>New passphrase for this device</label>
              <input
                type="password"
                value={importPassphrase}
                onChange={(e) => setImportPassphrase(e.target.value)}
                placeholder="Min 8 characters"
              />
              <button
                className="primary auth-submit"
                disabled={busy || !isValidImportSeed(importSeed) || importPassphrase.length < 8}
                onClick={() => onImport(importSeed, importPassphrase)}
              >
                Import wallet
              </button>
            </>
          )}

          {welcomeTab === "backup" && (
            <>
              <p className="muted small-note">
                Restore from encrypted JSON backup (Security → Download backup). Same passphrase as
                export.
              </p>
              <input
                ref={backupInputRef}
                type="file"
                accept=".json,application/json"
                style={{ display: "none" }}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void loadBackupFile(file).catch(() => undefined);
                  e.target.value = "";
                }}
              />
              <button type="button" disabled={busy} onClick={() => backupInputRef.current?.click()}>
                Choose backup file
              </button>
              {backupFileName ? <p className="muted small-note">Selected: {backupFileName}</p> : null}
              {backupPreview ? (
                <p className="muted small-note">Wallet in backup: {backupPreview}</p>
              ) : null}
              <label>Or paste backup JSON</label>
              <textarea
                className="textarea mono"
                value={backupJson}
                onChange={(e) => {
                  setBackupJson(e.target.value);
                  setBackupDeleteSource(undefined);
                  setBackupFileName(null);
                  setBackupPreview(null);
                }}
                placeholder='{"metadata":{...},"ciphertext":"..."}'
                rows={5}
              />
              <label>Backup passphrase</label>
              <input
                type="password"
                value={backupPassphrase}
                onChange={(e) => setBackupPassphrase(e.target.value)}
                placeholder="Passphrase used when backup was created"
              />
              <button
                className="primary auth-submit"
                disabled={busy || !backupJson.trim() || backupPassphrase.length < 8}
                onClick={() =>
                  onImportBackup(backupJson, backupPassphrase, backupDeleteSource ?? null)
                }
              >
                Restore from backup
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}