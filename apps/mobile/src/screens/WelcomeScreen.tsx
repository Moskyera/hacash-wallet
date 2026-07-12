import { useRef, useState } from "react";
import Toast from "../components/Toast";
import WalletLogo from "../components/WalletLogo";
import { api } from "../api";
import type { ToastKind } from "../hooks/useToast";
import { readBackupJsonFile } from "../utils/readBackupFile";

type WelcomeTab = "create" | "import" | "backup" | "watch";

type Props = {
  walletNameDraft: string;
  setWalletNameDraft: (v: string) => void;
  passphrase: string;
  setPassphrase: (v: string) => void;
  seed: string;
  setSeed: (v: string) => void;
  watchAddress: string;
  setWatchAddress: (v: string) => void;
  busy: boolean;
  onCreate: () => void;
  onImport: () => void;
  onImportBackup: (json: string, passphrase: string, deleteSource?: string | null) => void;
  onWatchOnly: () => void;
  toast: { msg: string; kind: ToastKind } | null;
};

export default function WelcomeScreen({
  walletNameDraft,
  setWalletNameDraft,
  passphrase,
  setPassphrase,
  seed,
  setSeed,
  watchAddress,
  setWatchAddress,
  busy,
  onCreate,
  onImport,
  onImportBackup,
  onWatchOnly,
  toast,
}: Props) {
  const [tab, setTab] = useState<WelcomeTab>("create");
  const [backupJson, setBackupJson] = useState("");
  const [backupPass, setBackupPass] = useState("");
  const [backupDeleteSource, setBackupDeleteSource] = useState<string | undefined>();
  const [backupFileName, setBackupFileName] = useState<string | null>(null);
  const [backupPreview, setBackupPreview] = useState<string | null>(null);
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
    <div className="auth-screen">
      <div className="auth-hero">
        <WalletLogo size="lg" />
        <p className="muted">Fast QR payments · L2 Fast Pay · Quantum-ready</p>
      </div>

      <div className="display-toggle">
        <button type="button" className={tab === "create" ? "selected" : ""} onClick={() => setTab("create")}>
          Create
        </button>
        <button type="button" className={tab === "import" ? "selected" : ""} onClick={() => setTab("import")}>
          Import
        </button>
        <button type="button" className={tab === "backup" ? "selected" : ""} onClick={() => setTab("backup")}>
          Restore
        </button>
        <button type="button" className={tab === "watch" ? "selected" : ""} onClick={() => setTab("watch")}>
          Watch-only
        </button>
      </div>

      {tab === "create" && (
        <div className="card">
          <h2>Create wallet</h2>
          <p className="muted">
            A unique random wallet is generated. Your passphrase only encrypts it on this phone — the
            same passphrase elsewhere creates a different wallet. Back up your secret in More →
            Security. Updating the app keeps your wallet; Delete wallet starts over.
          </p>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. My Hacash"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          <label className="label">Encryption passphrase</label>
          <input
            type="password"
            placeholder="Encrypts wallet on this device (min 8 chars)"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button className="primary" disabled={busy || !passphrase} onClick={() => void onCreate()}>
            Create wallet
          </button>
        </div>
      )}

      {tab === "import" && (
        <div className="card">
          <h2>Import wallet</h2>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. My Hacash"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          <label className="label">Secret hex or legacy passphrase</label>
          <textarea
            placeholder="64-char hex, or legacy passphrase from older wallet versions"
            value={seed}
            onChange={(e) => setSeed(e.target.value)}
          />
          <label className="label">Passphrase</label>
          <input
            type="password"
            placeholder="Encryption passphrase"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button className="primary" disabled={busy || !seed || !passphrase} onClick={() => void onImport()}>
            Import
          </button>
        </div>
      )}

      {tab === "backup" && (
        <div className="card">
          <h2>Restore backup</h2>
          <p className="muted">
            Use the encrypted JSON from More → Security → Download backup. Passphrase must match the
            one used at export. The file is deleted after restore when possible.
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
          <button type="button" className="primary" disabled={busy} onClick={() => backupInputRef.current?.click()}>
            Choose backup file
          </button>
          {backupFileName ? <p className="muted small">Selected: {backupFileName}</p> : null}
          {backupPreview ? <p className="muted small">Wallet: {backupPreview}</p> : null}
          <label className="label">Or paste backup JSON</label>
          <textarea
            value={backupJson}
            onChange={(e) => {
              setBackupJson(e.target.value);
              setBackupDeleteSource(undefined);
              setBackupFileName(null);
              setBackupPreview(null);
            }}
            placeholder='{"metadata":{...},"ciphertext":"..."}'
          />
          <label className="label">Backup passphrase</label>
          <input
            type="password"
            placeholder="Same passphrase as when you exported"
            value={backupPass}
            onChange={(e) => setBackupPass(e.target.value)}
          />
          <button
            type="button"
            className="primary"
            disabled={busy || !backupJson.trim() || backupPass.length < 8}
            onClick={() => onImportBackup(backupJson, backupPass, backupDeleteSource ?? null)}
          >
            Restore wallet
          </button>
        </div>
      )}

      {tab === "watch" && (
        <div className="card">
          <h2>Watch-only</h2>
          <p className="muted">Monitor balances and receive payments. Cannot sign transactions.</p>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. Cold watch"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          <label className="label">Hacash address</label>
          <input
            placeholder="1ABC…"
            value={watchAddress}
            onChange={(e) => setWatchAddress(e.target.value)}
          />
          <button
            className="primary"
            disabled={busy || !watchAddress.trim().startsWith("1")}
            onClick={() => void onWatchOnly()}
          >
            Open watch-only
          </button>
        </div>
      )}

      {toast && <Toast message={toast.msg} kind={toast.kind} />}
    </div>
  );
}