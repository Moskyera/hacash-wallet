import { useCallback, useEffect, useState } from "react";
import { api, HubFeePayer, SendOptions, SendPreview, WalletSettings } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { runWebAuthnAuth, webAuthnClientOrigin } from "../webauthn";
import { sendSuccessMessage } from "../fastPayUi";
import type { PaymentQrPayload } from "../paymentQr";
import type { Screen } from "../screens/types";
import type { WalletStatus } from "../api";

type Notify = (msg: string, kind: "error" | "info") => void;

export function useHacSend(opts: {
  settings: WalletSettings | null;
  status: WalletStatus | null;
  nativeBioAvailable: boolean;
  setScreen: (s: Screen) => void;
  refreshBalance: () => Promise<void>;
  refreshHistory: () => Promise<void>;
  refreshSettings: () => Promise<WalletSettings>;
  setLastTxHash: (hash: string) => void;
  clearMessages: () => void;
  onError: (msg: string) => void;
  onInfo: (msg: string) => void;
  setBusy: (b: boolean) => void;
  busy: boolean;
}) {
  const {
    settings,
    status,
    nativeBioAvailable,
    setScreen,
    refreshBalance,
    refreshHistory,
    refreshSettings,
    setLastTxHash,
    clearMessages,
    onError,
    onInfo,
    setBusy,
    busy,
  } = opts;

  const [sendTo, setSendTo] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [sendHubFeePayer, setSendHubFeePayer] = useState<HubFeePayer>("sender");
  const [sendForceL1, setSendForceL1] = useState(false);
  const [showSendOptions, setShowSendOptions] = useState(false);
  const [sendQrScanOpen, setSendQrScanOpen] = useState(false);
  const [preview, setPreview] = useState<SendPreview | null>(null);

  useEffect(() => {
    if (!settings) return;
    setSendHubFeePayer(settings.send?.hub_fee_payer ?? "sender");
    setSendForceL1(!(settings.send?.prefer_fast_pay ?? true));
  }, [settings?.send?.hub_fee_payer, settings?.send?.prefer_fast_pay, settings]);

  const currentSendOptions = useCallback(
    (): SendOptions => ({
      hub_fee_payer: sendHubFeePayer,
      force_l1: sendForceL1,
    }),
    [sendHubFeePayer, sendForceL1],
  );

  const persistSendPreferences = useCallback(
    async (hubFeePayer: HubFeePayer, forceL1: boolean) => {
      if (!settings) return;
      const next = {
        ...settings,
        send: {
          hub_fee_payer: hubFeePayer,
          prefer_fast_pay: !forceL1,
        },
      };
      await api.updateSettings(next);
      await refreshSettings();
    },
    [settings, refreshSettings],
  );

  const openQrPay = useCallback(() => {
    clearMessages();
    setPreview(null);
    setSendQrScanOpen(true);
    setScreen("send");
  }, [clearMessages, setScreen]);

  const handlePaymentQr = useCallback(
    async (payload: PaymentQrPayload) => {
      clearMessages();
      setSendQrScanOpen(false);
      setSendTo(payload.address);
      const amount = payload.amount_mei;
      if (amount != null && amount > 0) {
        setSendAmount(String(amount));
        setBusy(true);
        try {
          const p = await api.previewSend(payload.address, amount, currentSendOptions());
          setPreview(p);
          onInfo(
            payload.label
              ? `QR payment (${payload.label}) — review and confirm.`
              : "QR payment loaded — review and confirm.",
          );
        } catch (e) {
          onError(formatInvokeError(e));
        } finally {
          setBusy(false);
        }
      } else {
        setSendAmount("");
        setPreview(null);
        onInfo("Address scanned — enter amount and tap Continue.");
      }
      setScreen("send");
    },
    [clearMessages, currentSendOptions, setScreen, setBusy, onInfo, onError],
  );

  const handlePreviewSend = useCallback(async () => {
    setBusy(true);
    clearMessages();
    setPreview(null);
    try {
      const p = await api.previewSend(sendTo.trim(), Number(sendAmount), currentSendOptions());
      setPreview(p);
    } catch (e) {
      onError(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }, [sendTo, sendAmount, currentSendOptions, clearMessages, setBusy, onError]);

  const handleConfirmSend = useCallback(async () => {
    setBusy(true);
    clearMessages();
    try {
      const amount = Number(sendAmount);
      const needs2fa =
        status?.security_profile === "paranoid" ||
        (status?.security_profile !== "paranoid" && amount >= 100);
      if (needs2fa && status?.webauthn_enabled) {
        onInfo("Complete WebAuthn (YubiKey / Windows Hello) in the system prompt…");
        const origin = webAuthnClientOrigin();
        const options = await api.webauthnAuthBegin(origin);
        const assertion = await runWebAuthnAuth(options);
        await api.webauthnAuthFinish(assertion);
      } else if (needs2fa) {
        if (nativeBioAvailable) {
          onInfo(
            "Amount ≥ 100 HAC: confirm in the Windows Hello / PIN dialog (check taskbar if hidden).",
          );
          await api.confirmBiometricNative();
        } else if (status?.webauthn_enabled) {
          const origin = webAuthnClientOrigin();
          const options = await api.webauthnAuthBegin(origin);
          const assertion = await runWebAuthnAuth(options);
          await api.webauthnAuthFinish(assertion);
        } else {
          throw new Error("Enable Windows Hello or register WebAuthn for large sends");
        }
      }
      const result = await api.sendHac(sendTo.trim(), amount, currentSendOptions());
      setLastTxHash(result.tx_hash);
      setPreview(null);
      setSendTo("");
      setSendAmount("");
      await refreshBalance();
      await refreshHistory();
      onInfo(sendSuccessMessage(result.rail, result.summary));
      setScreen("home");
    } catch (e) {
      onError(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }, [
    sendTo,
    sendAmount,
    status,
    nativeBioAvailable,
    currentSendOptions,
    clearMessages,
    setBusy,
    setLastTxHash,
    refreshBalance,
    refreshHistory,
    onInfo,
    onError,
    setScreen,
  ]);

  const clearPreview = useCallback(() => setPreview(null), []);

  return {
    sendTo,
    setSendTo,
    sendAmount,
    setSendAmount,
    sendHubFeePayer,
    setSendHubFeePayer,
    sendForceL1,
    setSendForceL1,
    showSendOptions,
    setShowSendOptions,
    sendQrScanOpen,
    setSendQrScanOpen,
    preview,
    setPreview,
    clearPreview,
    currentSendOptions,
    persistSendPreferences,
    openQrPay,
    handlePaymentQr,
    handlePreviewSend,
    handleConfirmSend,
    busy,
  };
}