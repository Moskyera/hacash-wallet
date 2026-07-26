import { useLocale } from "@hacash/wallet-ui";
import { useState } from "react";
import { WalletStatus } from "../api";

type Props = {
  status: WalletStatus | null;
  webauthnReady: boolean;
  nativeBioAvailable: boolean;
  busy: boolean;
  onRegisterWebAuthn: (currentPassphrase: string) => void;
  onSetProfile: (profile: string, currentPassphrase: string) => void;
  onSetHardwareMode: (
    mode: "software" | "webauthn_gate" | "airgap_only" | "watch_only",
    currentPassphrase: string,
  ) => void;
};

export default function SecurityInfoScreen({
  status,
  webauthnReady,
  nativeBioAvailable,
  busy,
  onRegisterWebAuthn,
  onSetProfile,
  onSetHardwareMode,
}: Props) {
  const { t } = useLocale();
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [coldVaultConfirmation, setColdVaultConfirmation] = useState("");
  const coldVault = status?.hardware_signing_mode === "airgap_only";
  const legacyKey = status?.legacy_key_derivation != null;
  const freshFactorAvailable = !!status?.webauthn_enabled || nativeBioAvailable;
  const runAuthenticated = (action: (passphrase: string) => void) => {
    const passphrase = currentPassphrase;
    setCurrentPassphrase("");
    action(passphrase);
  };

  return (
    <>
      <div className="security-grid">
        <div className="security-item done">
          <h4>Encrypted vault</h4>
          <p>Argon2id and AES-256-GCM protect the vault. Keys are decrypted in memory while unlocked.</p>
        </div>
        <div className="security-item done">
          <h4>Local signing</h4>
          <p>Transactions are signed in the Rust core. The private key is never sent to the node API.</p>
        </div>
        <div className="security-item done">
          <h4>Istanbul transaction safety checks</h4>
          <p>Address format, balance, and large-transfer warnings are checked before every send.</p>
        </div>
        <div className={`security-item ${status?.webauthn_enabled ? "done" : "soon"}`}>
          <h4>YubiKey / Windows Hello</h4>
          <p>
            {t("security.webauthnSoftwareGateHint")}
            {status?.webauthn_enabled ? " Registered." : " Not registered yet."}
          </p>
        </div>
      </div>

      <div className="info-box">
        <strong>Enable YubiKey or Windows Hello</strong>
        <ol style={{ margin: "0.5rem 0 0", paddingLeft: "1.25rem" }}>
          <li>Plug in your YubiKey, or use built-in Windows Hello.</li>
          <li>
            Enter the current wallet passphrase, select <strong>Register WebAuthn</strong>,
            and follow the system prompt.
          </li>
          <li>
            Optional: choose <strong>Paranoid profile</strong> for stricter timeouts and
            WebAuthn on every send.
          </li>
          <li>
            Optional: set <strong>WebAuthn gate (all signs)</strong> to require a fresh
            second factor before every transaction.
          </li>
        </ol>
      </div>

      <label>Current wallet passphrase</label>
      <input
        type="password"
        value={currentPassphrase}
        autoComplete="current-password"
        onChange={(event) => setCurrentPassphrase(event.target.value)}
      />
      <p className="muted">Required to authenticate every security-policy change.</p>

      <div className="actions-row">
        <button
          disabled={busy || !webauthnReady || !currentPassphrase}
          onClick={() => runAuthenticated(onRegisterWebAuthn)}
        >
          Register WebAuthn
        </button>
      </div>

      <div className="actions-row">
        <button
          className={status?.security_profile === "balanced" ? "primary" : ""}
          disabled={busy || coldVault || !currentPassphrase}
          onClick={() =>
            runAuthenticated((passphrase) => onSetProfile("balanced", passphrase))
          }
        >
          Balanced profile
        </button>
        <button
          className={status?.security_profile === "paranoid" ? "primary" : ""}
          disabled={busy || coldVault || !currentPassphrase}
          onClick={() =>
            runAuthenticated((passphrase) => onSetProfile("paranoid", passphrase))
          }
        >
          Paranoid profile
        </button>
      </div>

      <h3>{t("security.signingPolicy")}</h3>
      <p className="muted">{t("security.softwareKeyCustodyHint")}</p>
      {legacyKey ? (
        <p className="warn-box">{t("security.legacyBrainwalletKeyWarning")}</p>
      ) : null}
      <div className="actions-row">
        <button
          className={status?.hardware_signing_mode === "software" ? "primary" : ""}
          disabled={busy || coldVault || status?.watch_only || !currentPassphrase}
          onClick={() =>
            runAuthenticated((passphrase) => onSetHardwareMode("software", passphrase))
          }
        >
          Software key
        </button>
        <button
          className={status?.hardware_signing_mode === "webauthn_gate" ? "primary" : ""}
          disabled={busy || coldVault || status?.watch_only || !currentPassphrase}
          onClick={() =>
            runAuthenticated((passphrase) => onSetHardwareMode("webauthn_gate", passphrase))
          }
        >
          WebAuthn gate (all signs)
        </button>
      </div>

      <div className={`security-item ${coldVault ? "done" : "soon"}`}>
        <h4>{t("security.coldVaultTitle")}</h4>
        {coldVault ? (
          <>
            <p>{t("security.coldVaultActiveHint")}</p>
            <p className="warn-box">{t("security.coldVaultRecoveryOnly")}</p>
          </>
        ) : (
          <>
            <p>{t("security.coldVaultActivationHint")}</p>
            <p className="warn-box">{t("security.coldVaultSoftwareLimit")}</p>
            {/* Desktop runs the same irreversible activation as mobile, so it needs
                the same warning to take a backup first. */}
            <p className="warn-box">{t("security.coldVaultBackupFirst")}</p>
            <label>{t("security.coldVaultConfirmLabel")}</label>
            <input
              value={coldVaultConfirmation}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => setColdVaultConfirmation(event.target.value)}
            />
            <button
              className="primary"
              disabled={
                busy ||
                status?.watch_only ||
                !currentPassphrase ||
                !freshFactorAvailable ||
                coldVaultConfirmation !== "ENABLE COLD VAULT"
              }
              onClick={() => {
                setColdVaultConfirmation("");
                runAuthenticated((passphrase) => onSetHardwareMode("airgap_only", passphrase));
              }}
            >
              {t("security.coldVaultActivate")}
            </button>
            {!freshFactorAvailable ? (
              <p className="warn-text">{t("security.coldVaultFactorRequired")}</p>
            ) : null}
          </>
        )}
      </div>
      <p className="muted">
        Profile: <strong>{status?.security_profile ?? "balanced"}</strong>. Balanced auto-locks
        after {status?.auto_lock_secs ?? 180}s. Paranoid uses shorter timeouts and requires
        WebAuthn before high-value sends.
      </p>
    </>
  );
}
