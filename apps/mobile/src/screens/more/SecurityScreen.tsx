import { useCallback, useEffect, useRef, useState } from "react";
import { api, type PlatformSecurityStatus, type WalletSettings, type WalletStatus } from "../../api";
import PrivateKeyQrDisplay from "../../components/PrivateKeyQrDisplay";
import { formatInvokeError } from "../../formatInvokeError";
import { copyWithPrivacyClear } from "../../privacy";
import { MIN_WALLET_PASS } from "../../quantumMeta";
import { BIOMETRIC_THRESHOLD_MEI } from "../../utils/appConstants";

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
  onChangePassphrase,
  onResetWallet,
  onLock,
  onRefresh,
  onToast,
  setBusy,
}: Props) {
  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [bioUnlockPass, setBioUnlockPass] = useState("");
  const [bioUnlockStatus, setBioUnlockStatus] = useState<{ enabled: boolean; configured: boolean } | null>(null);
  const [privateKeyPass, setPrivateKeyPass] = useState("");
  const [privateKey, setPrivateKey] = useState<string | null>(null);
  const privateKeyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const hidePrivateKey = useCallback(() => {
    setPrivateKey(null);
    if (privateKeyTimer.current) {
      clearTimeout(privateKeyTimer.current);
      privateKeyTimer.current = null;
    }
  }, []);

  useEffect(() => {
    void api.biometricUnlockStatus().then(setBioUnlockStatus).catch(() => setBioUnlockStatus(null));
  }, [settings?.biometric_unlock_enabled]);

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
        <h2>Private key</h2>
        <p className="muted small">
          Back up your wallet offline: reveal the key and scan the QR on a new phone (Welcome → Import → Scan QR).
          Keep your screen private — anyone nearby can read the key.
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
                onToast("Private key revealed. Hides in 60s.", "info");
                if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
                privateKeyTimer.current = setTimeout(() => hidePrivateKey(), 60_000);
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
            <PrivateKeyQrDisplay privateKeyHex={privateKey} />
            <button
              type="button"
              style={{ marginTop: "0.5rem" }}
              onClick={() =>
                void copyWithPrivacyClear(privateKey, clipboardSecs).then(() => onToast("Private key copied.", "success"))
              }
            >
              Copy
            </button>
            <button type="button" style={{ marginTop: "0.5rem", marginLeft: "0.5rem" }} onClick={hidePrivateKey}>
              Hide
            </button>
          </>
        ) : null}
      </div>
      <div className="card">
        <h2>Delete wallet</h2>
        <p className="muted">
          Removes this wallet from the phone so you can create or import a different one. Export your private key
          via QR first if you need to recover funds later.
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
        <p className="muted">Balanced is default. Paranoid requires biometric confirmation for every send.</p>
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
            : "No biometric sensor detected. Large sends may fail without fingerprint confirmation."}
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
      <button type="button" onClick={() => void onLock()}>
        Lock wallet
      </button>
    </>
  );
}