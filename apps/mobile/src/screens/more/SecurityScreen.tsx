import { useCallback, useEffect, useRef, useState } from "react";
import { api, type PlatformSecurityStatus, type WalletSettings, type WalletStatus } from "../../api";
import PrivateKeyQrDisplay from "../../components/PrivateKeyQrDisplay";
import { formatInvokeError } from "../../formatInvokeError";
import { useLocale } from "../../locale";
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
  const { t } = useLocale();
  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [bioUnlockPass, setBioUnlockPass] = useState("");
  const [bioUnlockStatus, setBioUnlockStatus] = useState<{ enabled: boolean; configured: boolean } | null>(null);
  const [privateKeyPass, setPrivateKeyPass] = useState("");
  const [backupPass, setBackupPass] = useState("");
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
        <h2>{t("security.privateKey")}</h2>
        <p className="muted small">{t("security.privateKeyMobileHint")}</p>
        <label className="label">{t("security.passphrase")}</label>
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
                onToast(t("security.privateKeyRevealed"), "info");
                if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
                privateKeyTimer.current = setTimeout(() => hidePrivateKey(), 60_000);
              })
              .catch((err) => onToast(formatInvokeError(err), "error"))
              .finally(() => setBusy(false));
          }}
        >
          {t("security.revealPrivateKey")}
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
                void copyWithPrivacyClear(privateKey, clipboardSecs).then(() =>
                  onToast(t("security.privateKeyCopied"), "success"),
                )
              }
            >
              {t("common.copy")}
            </button>
            <button type="button" style={{ marginTop: "0.5rem", marginLeft: "0.5rem" }} onClick={hidePrivateKey}>
              {t("common.hide")}
            </button>
          </>
        ) : null}
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
        <p className="muted">{t("security.deleteWalletHint")}</p>
        <button type="button" disabled={busy} onClick={onResetWallet}>
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
        <p className="muted">{t("security.profileHint")}</p>
        <div className="display-toggle">
          <button
            type="button"
            className={status?.security_profile !== "paranoid" ? "selected" : ""}
            disabled={busy || watchOnly}
            onClick={() =>
              void api
                .setSecurityProfile("balanced")
                .then(() => onRefresh())
                .then(() => onToast(t("security.profileUpdated", { profile: t("security.balanced") }), "success"))
            }
          >
            {t("security.balanced")}
          </button>
          <button
            type="button"
            className={status?.security_profile === "paranoid" ? "selected" : ""}
            disabled={busy || watchOnly}
            onClick={() =>
              void api
                .setSecurityProfile("paranoid")
                .then(() => onRefresh())
                .then(() => onToast(t("security.profileUpdated", { profile: t("security.paranoid") }), "success"))
            }
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
        <h2>{t("security.biometricUnlock")}</h2>
        <p className="muted small">
          {platformSec?.native_biometric_available
            ? t("security.biometricOpenWith", {
                kind: platformSec.biometric_kind ?? t("security.biometric"),
              })
            : t("security.noBiometricSensor")}
        </p>
        {bioUnlockStatus?.enabled && bioUnlockStatus.configured ? (
          <p className="muted small">{t("security.biometricUnlockActive")}</p>
        ) : null}
        {!bioUnlockStatus?.configured && platformSec?.native_biometric_available ? (
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
        <div className="toggle-row">
          <span>{t("security.useBiometricForSends")}</span>
          <input
            type="checkbox"
            checked={settings?.biometric_send_enabled ?? true}
            disabled={busy || watchOnly || !platformSec?.native_biometric_available}
            onChange={(e) => {
              if (!settings) return;
              void api
                .updateSettings({ ...settings, biometric_send_enabled: e.target.checked })
                .then(() => onRefresh())
                .then(() => onToast(t(e.target.checked ? "security.biometricConfirmOn" : "security.biometricConfirmOff"), "success"))
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
              .then(() => onToast(t("security.biometricTestOk"), "success"))
              .catch((err) => onToast(formatInvokeError(err), "error"))
              .finally(() => setBusy(false));
          }}
        >
          {t("security.testBiometric")}
        </button>
      </div>
      <button type="button" onClick={() => void onLock()}>
        {t("security.lockWallet")}
      </button>
    </>
  );
}
