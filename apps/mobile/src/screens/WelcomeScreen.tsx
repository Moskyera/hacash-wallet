import {
  isValidHacashAddress,
  MIN_NEW_WALLET_PASSPHRASE_LENGTH,
} from "@hacash/wallet-ui";
import { useRef, useState } from "react";
import { api, type BackupPreview } from "../api";
import Toast from "../components/Toast";
import WalletLogo from "../components/WalletLogo";
import PrivateKeyQrScanner from "../components/PrivateKeyQrScanner";
import type { ToastKind } from "../hooks/useToast";
import { useLocale } from "../locale";

const MAX_BACKUP_FILE_BYTES = 64 * 1024 * 1024;

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
  onRestoreBackup: (json: string, passphrase: string, allowLegacy: boolean) => void;
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
  onRestoreBackup,
  onWatchOnly,
  toast,
}: Props) {
  const { t } = useLocale();
  const [tab, setTab] = useState<WelcomeTab>("create");
  const [showQrScan, setShowQrScan] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [backupJson, setBackupJson] = useState("");
  const [backupPreview, setBackupPreview] = useState<BackupPreview | null>(null);
  const [backupError, setBackupError] = useState<string | null>(null);
  const [legacyLossAccepted, setLegacyLossAccepted] = useState(false);
  const backupInputRef = useRef<HTMLInputElement>(null);

  const loadBackupFile = async (file: File) => {
    setBackupError(null);
    setBackupPreview(null);
    setLegacyLossAccepted(false);
    if (file.size < 1 || file.size > MAX_BACKUP_FILE_BYTES) {
      setBackupJson("");
      setBackupError("Backup file size must be between 1 byte and 64 MiB.");
      return;
    }
    try {
      const json = await file.text();
      const preview = await api.previewBackup(json);
      setBackupJson(json);
      setBackupPreview(preview);
    } catch (error) {
      setBackupJson("");
      setBackupError(String(error));
    }
  };

  return (
    <div className="auth-screen">
      <div className="auth-hero">
        <WalletLogo size="lg" />
        <p className="muted small">{t("welcome.capabilities")}</p>
      </div>

      <div className="display-toggle">
        <button type="button" className={tab === "create" ? "selected" : ""} onClick={() => setTab("create")}>
          Create
        </button>
        <button type="button" className={tab === "import" ? "selected" : ""} onClick={() => setTab("import")}>
          Import
        </button>
        <button
          type="button"
          className={tab === "backup" ? "selected" : ""}
          onClick={() => setTab("backup")}
        >
          Restore
        </button>
        <button type="button" className={tab === "watch" ? "selected" : ""} onClick={() => setTab("watch")}>
          Watch
        </button>
      </div>

      {tab === "create" && (
        <div className="card">
          <h2>Create wallet</h2>
          <p className="muted small">New wallet on this phone.</p>
          <p className="muted small">
            Export an encrypted backup from Security and keep it offline before deleting the app.
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
            placeholder={`Minimum ${MIN_NEW_WALLET_PASSPHRASE_LENGTH} characters`}
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button
            className="primary"
            disabled={busy || passphrase.length < MIN_NEW_WALLET_PASSPHRASE_LENGTH}
            onClick={() => void onCreate()}
          >
            Create wallet
          </button>
        </div>
      )}

      {tab === "import" && (
        <div className="card">
          <h2>Import wallet</h2>
          <p className="muted small">
            Scan a private-key QR only from a trusted existing wallet or offline backup tool.
          </p>
          <p className="muted small">Or paste hex or old passphrase below.</p>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. My Hacash"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          {!showQrScan ? (
            <button
              type="button"
              className="primary"
              style={{ marginBottom: "0.75rem" }}
              disabled={busy}
              onClick={() => {
                setScanError(null);
                setShowQrScan(true);
              }}
            >
              Scan private key QR
            </button>
          ) : (
            <>
              <PrivateKeyQrScanner
                disabled={busy}
                onDetected={(hex) => {
                  setSeed(hex);
                  setScanError(null);
                  setShowQrScan(false);
                }}
                onError={(msg) => setScanError(msg)}
              />
              <button type="button" disabled={busy} onClick={() => setShowQrScan(false)}>
                Cancel scan
              </button>
            </>
          )}
          {scanError ? <p className="warn-text">{scanError}</p> : null}
          <label className="label">Secret hex or legacy passphrase</label>
          <textarea
            placeholder="64 character hex or old passphrase"
            value={seed}
            onChange={(e) => setSeed(e.target.value)}
          />
          <label className="label">Passphrase</label>
          <input
            type="password"
            placeholder={`Minimum ${MIN_NEW_WALLET_PASSPHRASE_LENGTH} characters`}
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
          />
          <button
            className="primary"
            disabled={busy || !seed.trim() || passphrase.length < MIN_NEW_WALLET_PASSPHRASE_LENGTH}
            onClick={() => void onImport()}
          >
            Import
          </button>
        </div>
      )}

      {tab === "backup" && (
        <div className="card">
          <h2>Restore authenticated backup</h2>
          <p className="muted small">
            Choose a full-wallet JSON backup and enter the same wallet passphrase. Biometric
            unlock is device-bound and must be enrolled again after restoration.
          </p>
          <input
            ref={backupInputRef}
            type="file"
            accept=".json,application/json"
            style={{ display: "none" }}
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void loadBackupFile(file);
              event.target.value = "";
            }}
          />
          <button type="button" disabled={busy} onClick={() => backupInputRef.current?.click()}>
            Choose backup file
          </button>
          {backupPreview ? (
            <>
              <p className="muted small">
                Wallet: {backupPreview.address} (verified after passphrase)
              </p>
              <p className="muted small">
                {backupPreview.format === "full_authenticated"
                  ? "Authenticated full backup"
                  : "Legacy classic-key-only backup"}
              </p>
              {backupPreview.warning ? <p className="warn-text">{backupPreview.warning}</p> : null}
              {backupPreview.requiresLegacyConfirmation ? (
                <label className="check-row">
                  <input
                    type="checkbox"
                    checked={legacyLossAccepted}
                    onChange={(event) => setLegacyLossAccepted(event.target.checked)}
                  />
                  I accept that this legacy backup has no Quantum keys, L2 dispute bills,
                  settings, or private app data.
                </label>
              ) : null}
            </>
          ) : null}
          {backupError ? <p className="warn-text">{backupError}</p> : null}
          <label className="label">Backup passphrase</label>
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
          />
          <button
            type="button"
            className="primary"
            disabled={
              busy ||
              !backupJson ||
              passphrase.length < 8 ||
              (backupPreview?.requiresLegacyConfirmation === true && !legacyLossAccepted)
            }
            onClick={() => onRestoreBackup(backupJson, passphrase, legacyLossAccepted)}
          >
            Restore backup
          </button>
        </div>
      )}

      {tab === "watch" && (
        <div className="card">
          <h2>Watch only</h2>
          <p className="muted small">View balance and receive. Cannot send.</p>
          <label className="label">Wallet name</label>
          <input
            placeholder="e.g. Cold watch"
            value={walletNameDraft}
            onChange={(e) => setWalletNameDraft(e.target.value)}
          />
          <label className="label">Hacash address</label>
          <input
            placeholder="Hacash address"
            value={watchAddress}
            onChange={(e) => setWatchAddress(e.target.value)}
          />
          <button
            className="primary"
            disabled={busy || !isValidHacashAddress(watchAddress)}
            onClick={() => void onWatchOnly()}
          >
            Open watch wallet
          </button>
        </div>
      )}

      {toast && <Toast message={toast.msg} kind={toast.kind} />}
    </div>
  );
}
