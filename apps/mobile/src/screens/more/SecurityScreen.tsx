import { useEffect, useState } from "react";
import { api, type PlatformSecurityStatus, type WalletSettings, type WalletStatus } from "../../api";
import { formatInvokeError } from "../../formatInvokeError";
import { useLocale } from "../../locale";
import { MIN_WALLET_PASS } from "../../quantumMeta";
import { BIOMETRIC_THRESHOLD_MEI } from "../../utils/appConstants";

type Props = {
  status: WalletStatus | null;
  settings: WalletSettings | null;
  platformSec: PlatformSecurityStatus | null;
  watchOnly: boolean;
  busy: boolean;
  walletNameDraft: string;
  setWalletNameDraft: (v: string) => void;
  onSaveWalletName: () => void;
  onChangePassphrase: (oldPass: string, newPass: string) => void;
  onResetWallet: (currentPassphrase: string | null, confirmationAddress: string) => Promise<boolean>;
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
  const { t } = useLocale();
  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [bioUnlockPass, setBioUnlockPass] = useState("");
  const [bioUnlockStatus, setBioUnlockStatus] = useState<{ enabled: boolean; configured: boolean } | null>(null);
  const [securityPassphrase, setSecurityPassphrase] = useState("");
  const [coldVaultPassphrase, setColdVaultPassphrase] = useState("");
  const [coldVaultConfirmation, setColdVaultConfirmation] = useState("");
  const [backupPass, setBackupPass] = useState("");
  const [resetPassphrase, setResetPassphrase] = useState("");
  const [resetAddress, setResetAddress] = useState("");
  const coldVault = status?.hardware_signing_mode === "airgap_only";
  const freshFactorAvailable = platformSec?.native_biometric_available === true;

  useEffect(() => {
    void api.biometricUnlockStatus().then(setBioUnlockStatus).catch(() => setBioUnlockStatus(null));
  }, [settings?.biometric_unlock_enabled]);

  return (
    <>
      <div className="card">
        <h2>{t("security.walletName")}</h2>
        <p className="muted">{t("security.walletNameHint")}</p>
        <label className="label">{t("security.displayName")}</label>
        <input
          value={walletNameDraft}
          onChange={(e) => setWalletNameDraft(e.target.value)}
          placeholder={t("security.walletPlaceholder")}
        />
        <button type="button" className="primary" onClick={onSaveWalletName}>
          {t("security.saveName")}
        </button>
      </div>
      <div className="card">
        <h2>{t("security.exportBackup")}</h2>
        <p className="muted small">{t("security.exportBackupHint")}</p>
        <label className="label">{t("security.exportPassphrase")}</label>
        <input
          type="password"
          value={backupPass}
          onChange={(event) => setBackupPass(event.target.value)}
        />
        <button
          type="button"
          className="primary"
          disabled={busy || watchOnly || !backupPass}
          onClick={() => {
            setBusy(true);
            void api
              .exportBackupToDownloads(backupPass)
              .then((destination) => {
                setBackupPass("");
                onToast(`${t("security.exportedBackupJson")}: ${destination}`, "success");
              })
              .catch((error) => onToast(formatInvokeError(error), "error"))
              .finally(() => setBusy(false));
          }}
        >
          {t("security.exportBackup")}
        </button>
      </div>
      <div className="card">
        <h2>{t("security.deleteWallet")}</h2>
        <p className="muted">
          {watchOnly
            ? "This permanently removes the watch-only wallet from this device. Type the complete wallet address exactly as shown."
            : "This permanently removes the signing wallet from this device. Confirm with the current passphrase and type the complete wallet address exactly as shown."}
        </p>
        <code className="mono wrap">{status?.address ?? "Wallet address unavailable"}</code>
        {!watchOnly ? (
          <>
            <label className="label">{t("security.currentPassphrase")}</label>
            <input
              type="password"
              autoComplete="current-password"
              value={resetPassphrase}
              onChange={(event) => setResetPassphrase(event.target.value)}
            />
          </>
        ) : null}
        <label className="label">Type the complete wallet address to confirm</label>
        <input
          value={resetAddress}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          onChange={(event) => setResetAddress(event.target.value)}
        />
        <button
          type="button"
          disabled={
            busy ||
            (!watchOnly && !resetPassphrase) ||
            !status?.address ||
            resetAddress !== status.address
          }
          onClick={() => {
            const passphrase = watchOnly ? null : resetPassphrase;
            const address = resetAddress;
            void onResetWallet(passphrase, address).then((removed) => {
              if (removed) {
                setResetPassphrase("");
                setResetAddress("");
              }
            });
          }}
        >
          {t("security.deleteFromDevice")}
        </button>
      </div>
      <div className="card">
        <h2>{t("security.changePassphrase")}</h2>
        <label className="label">{t("security.currentPassphrase")}</label>
        <input type="password" value={oldPass} onChange={(e) => setOldPass(e.target.value)} />
        <label className="label">{t("security.newPassphrase")}</label>
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
          {t("security.updatePassphrase")}
        </button>
        {newPass.length > 0 && newPass.length < MIN_WALLET_PASS ? (
          <p className="warn-text">
            {t("security.passphraseMin", { count: MIN_WALLET_PASS })}
          </p>
        ) : null}
      </div>
      <div className="card">
        <h2>{t("security.profile")}</h2>
        <p className="muted">{t("security.paranoidDesktopOnly")}</p>
        <label className="label">{t("security.currentPassphrase")}</label>
        <input
          type="password"
          value={securityPassphrase}
          autoComplete="current-password"
          onChange={(event) => setSecurityPassphrase(event.target.value)}
        />
        <div className="display-toggle">
          <button
            type="button"
            className={status?.security_profile !== "paranoid" ? "selected" : ""}
            disabled={busy || coldVault || watchOnly || !securityPassphrase}
            onClick={() => {
              const passphrase = securityPassphrase;
              setSecurityPassphrase("");
              setBusy(true);
              void api
                .setSecurityProfile("balanced", passphrase)
                .then(() => onRefresh())
                .then(() => onToast(t("security.profileUpdated", { profile: t("security.balanced") }), "success"))
                .catch((error) => onToast(formatInvokeError(error), "error"))
                .finally(() => setBusy(false));
            }}
          >
            {t("security.balanced")}
          </button>
          <button
            type="button"
            className={status?.security_profile === "paranoid" ? "selected" : ""}
            disabled
          >
            {t("security.paranoid")}
          </button>
        </div>
        <p className="muted small">
          {t("security.currentProfile", {
            profile: t(status?.security_profile === "paranoid" ? "security.paranoid" : "security.balanced"),
          })}
        </p>
      </div>
      <div className="card">
        <h2>{t("security.signingPolicy")}</h2>
        <p className="muted small">{t("security.softwareKeyCustodyHint")}</p>
        <h3>{t("security.coldVaultTitle")}</h3>
        {coldVault ? (
          <>
            <p className="muted small">{t("security.coldVaultActiveHint")}</p>
            <p className="warn-text">{t("security.coldVaultRecoveryOnly")}</p>
          </>
        ) : (
          <>
            <p className="muted small">{t("security.coldVaultActivationHint")}</p>
            <p className="warn-text">{t("security.coldVaultSoftwareLimit")}</p>
            <label className="label">{t("security.currentPassphrase")}</label>
            <input
              type="password"
              autoComplete="current-password"
              value={coldVaultPassphrase}
              onChange={(event) => setColdVaultPassphrase(event.target.value)}
            />
            <label className="label">{t("security.coldVaultConfirmLabel")}</label>
            <input
              value={coldVaultConfirmation}
              autoComplete="off"
              autoCapitalize="characters"
              autoCorrect="off"
              spellCheck={false}
              onChange={(event) => setColdVaultConfirmation(event.target.value)}
            />
            <button
              type="button"
              className="primary"
              disabled={
                busy ||
                watchOnly ||
                !freshFactorAvailable ||
                !coldVaultPassphrase ||
                coldVaultConfirmation !== "ENABLE COLD VAULT"
              }
              onClick={() => {
                const passphrase = coldVaultPassphrase;
                setColdVaultPassphrase("");
                setColdVaultConfirmation("");
                setBusy(true);
                void api
                  .setHardwareMode("airgap_only", passphrase)
                  .then(() => onRefresh())
                  .then(() => api.biometricUnlockStatus())
                  .then((nextStatus) => {
                    setBioUnlockStatus(nextStatus);
                    onToast(t("security.coldVaultActivatedToast"), "success");
                  })
                  .catch((error) => onToast(formatInvokeError(error), "error"))
                  .finally(() => setBusy(false));
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
      <div className="card">
        <h2>{t("security.biometricUnlock")}</h2>
        <p className="muted small">
          {coldVault
            ? t("security.coldVaultBiometricBlocked")
            : platformSec?.native_biometric_available
            ? t("security.biometricOpenWith", {
                kind: platformSec.biometric_kind ?? t("security.biometric"),
              })
            : t("security.noBiometricSensor")}
        </p>
        {bioUnlockStatus?.enabled && bioUnlockStatus.configured ? (
          <p className="muted small">{t("security.biometricUnlockActive")}</p>
        ) : null}
        {!coldVault && !bioUnlockStatus?.configured && platformSec?.native_biometric_available ? (
          <>
            <label className="label">{t("security.passphraseToEnable")}</label>
            <input
              type="password"
              value={bioUnlockPass}
              onChange={(e) => setBioUnlockPass(e.target.value)}
              placeholder={t("security.enterWalletPassphrase")}
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
                    onToast(t("security.biometricUnlockEnabled"), "success");
                  })
                  .catch((err) => onToast(formatInvokeError(err), "error"))
                  .finally(() => setBusy(false));
              }}
            >
              {t("security.enableBiometricUnlock")}
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
                  onToast(t("security.biometricUnlockDisabled"), "success");
                })
                .catch((err) => onToast(formatInvokeError(err), "error"))
                .finally(() => setBusy(false));
            }}
          >
            {t("security.disableBiometricUnlock")}
          </button>
        ) : null}
      </div>
      <div className="card">
        <h2>{t("security.biometricConfirm")}</h2>
        <p className="muted small">
          {platformSec?.native_biometric_available
            ? t("security.biometricConfirmSends", {
                amount: BIOMETRIC_THRESHOLD_MEI,
                kind: platformSec.biometric_kind ?? t("security.biometric"),
              })
            : t("security.noBiometricLargeSend")}
        </p>
        <p className="muted small">{t("security.biometricConfirmOn")}</p>
        {/* Never use the production send authorization as a biometric test. */}
      </div>
      <button type="button" onClick={() => void onLock()}>
        {t("security.lockWallet")}
      </button>
    </>
  );
}
