import { useEffect, useRef, useState } from "react";
import { api, type PlatformSecurityStatus, type WalletSettings, type WalletStatus } from "../../api";
import { formatInvokeError } from "../../formatInvokeError";
import { copyWithPrivacyClear } from "../../privacy";
import { MIN_WALLET_PASS } from "../../quantumMeta";
import { BIOMETRIC_THRESHOLD_MEI } from "../../utils/appConstants";
import {
  runWebAuthnAuth,
  runWebAuthnRegister,
  webAuthnAvailable,
  webAuthnClientOrigin,
} from "../../webauthn";

type Props = {
  status: WalletStatus | null;
  settings: WalletSettings | null;
  platformSec: PlatformSecurityStatus | null;
  watchOnly: boolean;
  busy: boolean;
  clipboardSecs: number;
  walletNameDraft: string;
  setWalletNameDraft: (v: string) => void;
  onSaveWalletName: () => void;
  onExportBackup: (passphrase: string) => void;
  onChangePassphrase: (oldPass: string, newPass: string) => void;
  onResetWallet: () => void;
  onLock: () => void;
  onRefresh: () => Promise<void>;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  setBusy: (b: boolean) => void;
};

export default function SecurityScreen({
  status,
  settings,
  platformSec,
  watchOnly,
  busy,
  clipboardSecs,
  walletNameDraft,
  setWalletNameDraft,
  onSaveWalletName,
  onExportBackup,
  onChangePassphrase,
  onResetWallet,
  onLock,
  onRefresh,
  onToast,
  setBusy,
}: Props) {
  const [backupPass, setBackupPass] = useState("");
  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [bioUnlockPass, setBioUnlockPass] = useState("");
  const [bioUnlockStatus, setBioUnlockStatus] = useState<{ enabled: boolean; configured: boolean } | null>(null);
  const [privateKeyPass, setPrivateKeyPass] = useState("");
  const [privateKey, setPrivateKey] = useState<string | null>(null);
  const [webauthnReady, setWebauthnReady] = useState(false);
  const privateKeyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    void api.biometricUnlockStatus().then(setBioUnlockStatus).catch(() => setBioUnlockStatus(null));
  }, [settings?.biometric_unlock_enabled]);

  useEffect(() => {
    void webAuthnAvailable().then(setWebauthnReady);
    return () => {
      if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
    };
  }, []);

  async function handleRegisterWebAuthn() {
    if (!webauthnReady) {
      onToast("WebAuthn is not available in this WebView.", "error");
      return;
    }
    setBusy(true);
    try {
      const options = await api.webauthnRegisterBegin(webAuthnClientOrigin());
      const cred = await runWebAuthnRegister(options);
      await api.webauthnRegisterFinish(cred);
      await onRefresh();
      onToast("WebAuthn passkey registered.", "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleTestWebAuthn() {
    if (!webauthnReady || !settings?.webauthn_enabled) return;
    setBusy(true);
    try {
      const options = await api.webauthnAuthBegin(webAuthnClientOrigin());
      const assertion = await runWebAuthnAuth(options);
      await api.webauthnAuthFinish(assertion);
      onToast("WebAuthn verification OK.", "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="card">
        <h2>Wallet name</h2>
        <p className="muted">Shown on the unlock screen instead of your address.</p>
        <label className="label">Display name</label>
        <input value={walletNameDraft} onChange={(e) => setWalletNameDraft(e.target.value)} placeholder="My Wallet" />
        <button type="button" className="primary" onClick={onSaveWalletName}>
          Save name
        </button>
      </div>
      <div className="card">
        <h2>Backup</h2>
        <p className="muted">
          Export encrypted JSON backup. Restore it on a new device via Welcome → Restore backup
          (same passphrase). Delete the file from Downloads after restoring.
        </p>
        <label className="label">Passphrase</label>
        <input type="password" value={backupPass} onChange={(e) => setBackupPass(e.target.value)} />
        <button
          type="button"
          className="primary"
          disabled={busy || !backupPass}
          onClick={() => {
            onExportBackup(backupPass);
            setBackupPass("");
          }}
        >
          Download backup
        </button>
      </div>
      <div className="card">
        <h2>Private key</h2>
        <p className="muted small">
          Advanced: view your wallet private key. Anyone with this key controls your funds. Never share it.
        </p>
        <label className="label">Passphrase</label>
        <input type="password" value={privateKeyPass} onChange={(e) => setPrivateKeyPass(e.target.value)} />
        <button
          type="button"
          className="primary"
          disabled={busy || watchOnly || !privateKeyPass}
          onClick={() => {
            setBusy(true);
            void api
              .exportPrivateKey(privateKeyPass)
              .then((hex) => {
                setPrivateKey(hex);
                setPrivateKeyPass("");
                onToast("Private key revealed. It will hide in 60s.", "info");
                if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
                privateKeyTimer.current = setTimeout(() => setPrivateKey(null), 60_000);
              })
              .catch((err) => onToast(formatInvokeError(err), "error"))
              .finally(() => setBusy(false));
          }}
        >
          Reveal private key
        </button>
        {privateKey ? (
          <>
            <p className="mono small" style={{ wordBreak: "break-all", marginTop: "0.75rem" }}>
              {privateKey}
            </p>
            <button
              type="button"
              style={{ marginTop: "0.5rem" }}
              onClick={() =>
                void copyWithPrivacyClear(privateKey, clipboardSecs).then(() => onToast("Private key copied.", "success"))
              }
            >
              Copy
            </button>
            <button
              type="button"
              style={{ marginTop: "0.5rem", marginLeft: "0.5rem" }}
              onClick={() => {
                setPrivateKey(null);
                if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
              }}
            >
              Hide
            </button>
          </>
        ) : null}
      </div>
      <div className="card">
        <h2>Delete wallet</h2>
        <p className="muted">
          Removes this wallet from the phone so you can create or import a different one. Export a backup first if you
          need to recover funds later.
        </p>
        <button type="button" disabled={busy} onClick={onResetWallet}>
          Delete wallet from device
        </button>
      </div>
      <div className="card">
        <h2>Change passphrase</h2>
        <label className="label">Current</label>
        <input type="password" value={oldPass} onChange={(e) => setOldPass(e.target.value)} />
        <label className="label">New</label>
        <input type="password" value={newPass} onChange={(e) => setNewPass(e.target.value)} />
        <button
          type="button"
          className="primary"
          disabled={busy || !oldPass || !newPass || newPass.length < MIN_WALLET_PASS}
          onClick={() => {
            onChangePassphrase(oldPass, newPass);
            setOldPass("");
            setNewPass("");
          }}
        >
          Update passphrase
        </button>
        {newPass.length > 0 && newPass.length < MIN_WALLET_PASS ? (
          <p className="warn-text">New passphrase must be at least {MIN_WALLET_PASS} characters.</p>
        ) : null}
      </div>
      <div className="card">
        <h2>Security profile</h2>
        <p className="muted">Balanced is default. Paranoid requires WebAuthn or biometrics for large sends.</p>
        <div className="display-toggle">
          <button
            type="button"
            className={status?.security_profile !== "paranoid" ? "selected" : ""}
            disabled={busy || watchOnly}
            onClick={() =>
              void api
                .setSecurityProfile("balanced")
                .then(() => onRefresh())
                .then(() => onToast("Profile: balanced", "success"))
            }
          >
            Balanced
          </button>
          <button
            type="button"
            className={status?.security_profile === "paranoid" ? "selected" : ""}
            disabled={busy || watchOnly}
            onClick={() =>
              void api
                .setSecurityProfile("paranoid")
                .then(() => onRefresh())
                .then(() => onToast("Profile: paranoid", "success"))
            }
          >
            Paranoid
          </button>
        </div>
        <p className="muted small">Current: {status?.security_profile ?? "balanced"}</p>
      </div>
      <div className="card">
        <h2>Biometric unlock</h2>
        <p className="muted small">
          {platformSec?.native_biometric_available
            ? `Open the wallet with ${platformSec.biometric_kind ?? "biometric"} instead of typing your passphrase.`
            : "No biometric sensor on this device."}
        </p>
        {bioUnlockStatus?.enabled && bioUnlockStatus.configured ? (
          <p className="muted small">Biometric unlock is active.</p>
        ) : null}
        {!bioUnlockStatus?.configured && platformSec?.native_biometric_available ? (
          <>
            <label className="label">Passphrase (to enable)</label>
            <input
              type="password"
              value={bioUnlockPass}
              onChange={(e) => setBioUnlockPass(e.target.value)}
              placeholder="Enter wallet passphrase"
            />
            <button
              type="button"
              className="primary"
              style={{ marginTop: "0.75rem", width: "100%" }}
              disabled={busy || watchOnly || !bioUnlockPass}
              onClick={() => {
                setBusy(true);
                void api
                  .enableBiometricUnlock(bioUnlockPass)
                  .then(() => onRefresh())
                  .then(() => api.biometricUnlockStatus())
                  .then((s) => {
                    setBioUnlockStatus(s);
                    setBioUnlockPass("");
                    onToast("Biometric unlock enabled.", "success");
                  })
                  .catch((err) => onToast(formatInvokeError(err), "error"))
                  .finally(() => setBusy(false));
              }}
            >
              Enable biometric unlock
            </button>
          </>
        ) : null}
        {bioUnlockStatus?.configured ? (
          <button
            type="button"
            style={{ marginTop: "0.75rem", width: "100%" }}
            disabled={busy || watchOnly}
            onClick={() => {
              setBusy(true);
              void api
                .disableBiometricUnlock()
                .then(() => onRefresh())
                .then(() => api.biometricUnlockStatus())
                .then((s) => {
                  setBioUnlockStatus(s);
                  onToast("Biometric unlock disabled.", "success");
                })
                .catch((err) => onToast(formatInvokeError(err), "error"))
                .finally(() => setBusy(false));
            }}
          >
            Disable biometric unlock
          </button>
        ) : null}
      </div>
      <div className="card">
        <h2>Biometric confirm</h2>
        <p className="muted small">
          {platformSec?.native_biometric_available
            ? `Confirm sends ≥ ${BIOMETRIC_THRESHOLD_MEI} HAC with ${platformSec.biometric_kind ?? "biometric"}.`
            : "No biometric sensor detected. Use a passkey instead, or keep sends below the limit."}
        </p>
        <div className="toggle-row">
          <span>Use biometric for sends</span>
          <input
            type="checkbox"
            checked={settings?.biometric_send_enabled ?? true}
            disabled={busy || watchOnly || !platformSec?.native_biometric_available}
            onChange={(e) => {
              if (!settings) return;
              void api
                .updateSettings({ ...settings, biometric_send_enabled: e.target.checked })
                .then(() => onRefresh())
                .then(() => onToast(e.target.checked ? "Biometric confirm on." : "Biometric confirm off.", "success"))
                .catch((err) => onToast(formatInvokeError(err), "error"));
            }}
          />
        </div>
        <button
          type="button"
          className="primary"
          style={{ marginTop: "0.75rem", width: "100%" }}
          disabled={busy || watchOnly || !platformSec?.native_biometric_available}
          onClick={() => {
            setBusy(true);
            void api
              .confirmBiometric()
              .then(() => onToast("Biometric test OK.", "success"))
              .catch((err) => onToast(formatInvokeError(err), "error"))
              .finally(() => setBusy(false));
          }}
        >
          Test biometric
        </button>
      </div>
      <div className="card">
        <h2>Passkey</h2>
        <p className="muted small">
          {settings?.webauthn_enabled
            ? "Registered. Used for paranoid profile and large sends when enabled."
            : "Register once to confirm large sends with your device passkey."}
        </p>
        <p className="muted small">App origin: {webAuthnClientOrigin() || "unknown"}</p>
        <div className="row-btns">
          <button type="button" className="primary" disabled={busy || !webauthnReady} onClick={() => void handleRegisterWebAuthn()}>
            Register passkey
          </button>
          <button type="button" disabled={busy || !settings?.webauthn_enabled} onClick={() => void handleTestWebAuthn()}>
            Test passkey
          </button>
        </div>
        {!webauthnReady ? (
          <p className="muted small">Passkey not available in this WebView. Update the app if this persists.</p>
        ) : null}
      </div>
      <button type="button" onClick={() => void onLock()}>
        Lock wallet
      </button>
    </>
  );
}