import {
  isValidHacashAddress,
  MIN_NEW_WALLET_PASSPHRASE_LENGTH,
} from "@hacash/wallet-ui";
import { useRef, useState } from "react";
import WalletLogo from "../components/WalletLogo";
import { api, type BackupPreview } from "../api";
import { readBackupJsonFile } from "../utils/readBackupFile";
import {
  compactSeed,
  isSecretHexSeed,
  looksLikeMistypedKey,
  type WelcomeTab,
} from "./types";

type Props = {
  busy: boolean;
  onCreate: (passphrase: string) => void;
  onImport: (seed: string, passphrase: string, expectedAddress: string) => void;
  onImportBackup: (
    json: string,
    passphrase: string,
    deleteSource?: string | null,
    allowLegacy?: boolean,
  ) => void;
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
  const [importExpectedAddress, setImportExpectedAddress] = useState("");
  const mistypedKey = looksLikeMistypedKey(importSeed);
  const legacyPhrase =
    importSeed.trim().length > 0 && !isSecretHexSeed(importSeed) && !mistypedKey;
  const [importPassphrase, setImportPassphrase] = useState("");
  const [watchAddress, setWatchAddress] = useState("");
  const [backupJson, setBackupJson] = useState("");
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [backupDeleteSource, setBackupDeleteSource] = useState<string | undefined>();
  const [backupPreview, setBackupPreview] = useState<BackupPreview | null>(null);
  const [legacyLossAccepted, setLegacyLossAccepted] = useState(false);
  const [backupFileName, setBackupFileName] = useState<string | null>(null);
  const backupInputRef = useRef<HTMLInputElement>(null);

  const loadBackupFile = async (file: File) => {
    const payload = await readBackupJsonFile(file);
    setBackupJson(payload.json);
    setBackupDeleteSource(payload.deleteSource);
    setBackupFileName(file.name);
    setBackupPreview(null);
    setLegacyLossAccepted(false);
    try {
      setBackupPreview(await api.previewBackup(payload.json));
    } catch {
      setBackupPreview(null);
    }
  };

  return (
    <div className="auth-layout auth-layout-welcome">
      <div className="auth-welcome">
        <div className="auth-hero">
          <WalletLogo size="lg" />
          <h1>Welcome to HPAY Wallet</h1>
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
                placeholder={`Minimum ${MIN_NEW_WALLET_PASSPHRASE_LENGTH} characters`}
              />
              <button
                className="primary auth-submit"
                disabled={busy || passphrase.length < MIN_NEW_WALLET_PASSPHRASE_LENGTH}
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
                placeholder="Hacash address"
              />
              <p className="muted small-note">
                Watch-only mode. No private key on this device. cannot send or sign.
              </p>
              <button
                className="primary auth-submit"
                disabled={busy || !isValidHacashAddress(watchAddress)}
                onClick={() => onWatchOnly(watchAddress)}
              >
                Add watch-only wallet
              </button>
            </>
          )}

          {welcomeTab === "import" && (
            <>
              <label>Private key (64-char hex)</label>
              <textarea
                className="textarea"
                value={importSeed}
                onChange={(e) => setImportSeed(e.target.value)}
                placeholder="64-char hex secret"
                rows={3}
              />
              <label>Address of the wallet you are importing</label>
              <input
                value={importExpectedAddress}
                autoComplete="off"
                spellCheck={false}
                placeholder="Hacash address this key belongs to"
                onChange={(e) => setImportExpectedAddress(e.target.value)}
              />
              <p className="muted small-note">
                A mistyped key is usually still a valid key, just a different
                wallet. Checking it against your address is what turns a silent
                wrong wallet into a clear error.
              </p>
              <label>New passphrase for this device</label>
              <input
                type="password"
                value={importPassphrase}
                onChange={(e) => setImportPassphrase(e.target.value)}
                placeholder={`Minimum ${MIN_NEW_WALLET_PASSPHRASE_LENGTH} characters`}
              />
              {importSeed.trim() && !isSecretHexSeed(importSeed) ? (
                <p className="warn-box">
                  {looksLikeMistypedKey(importSeed)
                    ? `A private key is exactly 64 hex characters and you entered ${compactSeed(importSeed).length}. Check for missing or extra characters.`
                    : "A private key is exactly 64 hex characters (0-9, a-f). This wallet cannot turn a phrase or passphrase into a key."}
                </p>
              ) : null}
              <button
                className="primary auth-submit"
                disabled={
                  busy ||
                  !isSecretHexSeed(importSeed) ||
                  !isValidHacashAddress(importExpectedAddress.trim()) ||
                  importPassphrase.length < MIN_NEW_WALLET_PASSPHRASE_LENGTH
                }
                onClick={() =>
                  onImport(importSeed, importPassphrase, importExpectedAddress.trim())
                }
              >
                Import wallet
              </button>
            </>
          )}

          {welcomeTab === "backup" && (
            <>
              <p className="muted small-note">
                Restore an authenticated full-wallet backup with the same wallet passphrase.
                Device-bound biometric unlock is never transferred and must be enrolled again.
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
                <div className="small-note">
                  <p className="muted">
                    Wallet in backup: {backupPreview.address} (verified after passphrase)
                  </p>
                  <p className="muted">
                    Format: {backupPreview.format === "full_authenticated" ? "Authenticated full backup" : "Legacy classic-key-only backup"}
                  </p>
                  {backupPreview.warning ? <p className="error">{backupPreview.warning}</p> : null}
                  {backupPreview.requiresLegacyConfirmation ? (
                    <label className="check-row">
                      <input
                        type="checkbox"
                        checked={legacyLossAccepted}
                        onChange={(event) => setLegacyLossAccepted(event.target.checked)}
                      />
                      I accept that this legacy backup permanently lacks Quantum keys, L2 dispute bills, settings, and private app data.
                    </label>
                  ) : null}
                </div>
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
                  setLegacyLossAccepted(false);
                }}
                placeholder='{"header":{"magic":"HACASH_WALLET_BACKUP"},"ciphertext_b64":"..."}'
                rows={5}
              />
              <label>Backup passphrase</label>
              <input
                type="password"
                value={backupPassphrase}
                onChange={(e) => setBackupPassphrase(e.target.value)}
                placeholder="Passphrase used when backup was created"
              />
              {/* Restoring writes over whatever wallet is on this device, so
                  it keeps the loud solid fill that `.primary` gave up. */}
              <button
                className="primary auth-submit irreversible-action"
                disabled={
                  busy ||
                  !backupJson.trim() ||
                  backupPassphrase.length < 8 ||
                  (backupPreview?.requiresLegacyConfirmation === true && !legacyLossAccepted)
                }
                onClick={() =>
                  onImportBackup(
                    backupJson,
                    backupPassphrase,
                    backupDeleteSource ?? null,
                    legacyLossAccepted,
                  )
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