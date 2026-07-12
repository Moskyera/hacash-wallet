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
    <section className="panel hero">
      <WalletLogo size="lg" />
      <h1>Your modern Hacash wallet</h1>
      <p>
        Encrypted keys on device. Send HAC in one tap. Instant Fast Pay when available,
        otherwise standard on-chain.
      </p>
      <div className="tab-row">
        <button
          type="button"
          className={welcomeTab === "create" ? "tab active" : "tab"}
          onClick={() => setWelcomeTab("create")}
        >
          Create
        </button>
        <button
          type="button"
          className={welcomeTab === "import" ? "tab active" : "tab"}
          onClick={() => setWelcomeTab("import")}
        >
          Import
        </button>
        <button
          type="button"
          className={welcomeTab === "backup" ? "tab active" : "tab"}
          onClick={() => setWelcomeTab("backup")}
        >
          Restore backup
        </button>
        <button
          type="button"
          className={welcomeTab === "watch" ? "tab active" : "tab"}
          onClick={() => setWelcomeTab("watch")}
        >
          Watch-only
        </button>
      </div>

      {welcomeTab === "create" && (
        <>
          <p className="muted">
            A unique random wallet is generated. Your passphrase only encrypts it on this device —
            the same passphrase on another phone creates a different wallet. Back up your secret in
            Security after creating.
          </p>
          <label>Encryption passphrase</label>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Passphrase (min 8 chars, 12+ recommended)"
          />
          <button
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
          <p className="muted">
            Sparrow-style watch-only. No private key on this device. Cannot send or sign.
          </p>
          <button
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
            placeholder="64-char hex secret, or legacy passphrase from older wallet versions"
            rows={3}
          />
          <label>New passphrase for this device</label>
          <input
            type="password"
            value={importPassphrase}
            onChange={(e) => setImportPassphrase(e.target.value)}
            placeholder="Passphrase (min 8 chars)"
          />
          <button
            disabled={
              busy || !isValidImportSeed(importSeed) || importPassphrase.length < 8
            }
            onClick={() => onImport(importSeed, importPassphrase)}
          >
            Import wallet
          </button>
        </>
      )}

      {welcomeTab === "backup" && (
        <>
          <p className="muted">
            Restore from an encrypted JSON backup (Security → Download backup). Use the same
            passphrase as when you exported. The backup file is deleted after a successful restore
            when possible.
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
          {backupFileName ? <p className="muted">Selected: {backupFileName}</p> : null}
          {backupPreview ? <p className="muted">Wallet in backup: {backupPreview}</p> : null}
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
          <label>Backup passphrase (same as export)</label>
          <input
            type="password"
            value={backupPassphrase}
            onChange={(e) => setBackupPassphrase(e.target.value)}
            placeholder="Passphrase used when backup was created"
          />
          <button
            disabled={busy || !backupJson.trim() || backupPassphrase.length < 8}
            onClick={() =>
              onImportBackup(backupJson, backupPassphrase, backupDeleteSource ?? null)
            }
          >
            Restore from backup
          </button>
        </>
      )}
    </section>
  );
}