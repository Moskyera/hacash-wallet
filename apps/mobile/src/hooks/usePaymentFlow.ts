import { useCallback, useState } from "react";
import { api, HubFeePayer, SendOptions, SendPreview, WalletSettings } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { applyPaymentPayload } from "../utils/applyPaymentPayload";
import { hapticSuccess } from "../utils/haptic";
import { maybeWebAuthnGate } from "../utils/webauthnGate";
import type { PaymentQrPayload } from "../paymentQr";
import type { PlatformSecurityStatus } from "../api";

export function usePaymentFlow(opts: {
  settings: WalletSettings | null;
  setSettings: (s: WalletSettings) => void;
  platformSec: PlatformSecurityStatus | null;
  watchOnly: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  refresh: () => Promise<void>;
  showToast: (msg: string, kind: "success" | "info" | "error") => void;
  onSent?: () => void;
}) {
  const { settings, setSettings, platformSec, busy, setBusy, refresh, showToast, onSent } = opts;

  const [sendTo, setSendTo] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [sendHubFeePayer, setSendHubFeePayer] = useState<HubFeePayer>("sender");
  const [sendForceL1, setSendForceL1] = useState(false);
  const [preview, setPreview] = useState<SendPreview | null>(null);
  const [payScanMode, setPayScanMode] = useState(false);

  const sendOptions = useCallback(
    (): SendOptions => ({
      hub_fee_payer: sendHubFeePayer,
      force_l1: sendForceL1,
    }),
    [sendHubFeePayer, sendForceL1],
  );

  const syncSendPrefsFromSettings = useCallback((cfg: WalletSettings) => {
    setSendHubFeePayer(cfg.send?.hub_fee_payer ?? "sender");
    setSendForceL1(!(cfg.send?.prefer_fast_pay ?? true));
  }, []);

  const persistSendPrefs = useCallback(
    async (hubFee: HubFeePayer, forceL1: boolean) => {
      if (!settings) return;
      const next: WalletSettings = {
        ...settings,
        send: { hub_fee_payer: hubFee, prefer_fast_pay: !forceL1 },
      };
      await api.updateSettings(next);
      setSettings(next);
    },
    [settings, setSettings],
  );

  const loadPaymentPayload = useCallback(
    async (payload: PaymentQrPayload, source: "qr" | "deeplink") => {
      setPayScanMode(false);
      setBusy(true);
      try {
        const result = await applyPaymentPayload({
          payload,
          sendOptions: sendOptions(),
          toast: showToast,
          withAmountMessage:
            source === "qr" ? "QR loaded — confirm payment." : "Payment link loaded — confirm below.",
          withoutAmountMessage:
            source === "qr" ? "Address scanned — enter amount." : "Address loaded — enter amount.",
        });
        setSendTo(result.sendTo);
        setSendAmount(result.sendAmount);
        setPreview(result.preview);
      } finally {
        setBusy(false);
      }
    },
    [sendOptions, setBusy, showToast],
  );

  const parseAmountMei = (raw: string): number | null => {
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0) return null;
    return n;
  };

  const handlePreviewSend = useCallback(async () => {
    const amountMei = parseAmountMei(sendAmount);
    if (!sendTo.trim() || amountMei == null) {
      showToast("Enter a valid recipient and amount.", "error");
      return;
    }
    setBusy(true);
    setPreview(null);
    try {
      const p = await api.previewSend(sendTo.trim(), amountMei, sendOptions());
      setPreview(p);
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [sendAmount, sendTo, sendOptions, setBusy, showToast]);

  const maybeSecondFactor = useCallback(
    async (amountMei: number): Promise<boolean> => {
      try {
        await maybeWebAuthnGate({
          amountMei,
          securityProfile: settings?.security_profile,
          webauthnEnabled: settings?.webauthn_enabled,
          nativeBiometricAvailable: platformSec?.native_biometric_available,
        });
        return true;
      } catch (e) {
        showToast(formatInvokeError(e), "error");
        return false;
      }
    },
    [platformSec, settings, showToast],
  );

  const handleConfirmSend = useCallback(async () => {
    if (!preview) return;
    const ok = await maybeSecondFactor(preview.amount_mei);
    if (!ok) return;
    setBusy(true);
    try {
      const result = await api.sendHac(preview.to, preview.amount_mei, sendOptions());
      setPreview(null);
      setSendTo("");
      setSendAmount("");
      setPayScanMode(false);
      showToast(`Sent via ${result.rail}`, "success");
      hapticSuccess();
      await refresh();
      onSent?.();
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [maybeSecondFactor, onSent, preview, refresh, sendOptions, setBusy, showToast]);

  const goToPayContact = useCallback((address: string, label?: string) => {
    setSendTo(address);
    setPreview(null);
    setPayScanMode(false);
    if (label) showToast(`Paying ${label}`, "info");
  }, [showToast]);

  const resetPreview = useCallback(() => setPreview(null), []);

  return {
    sendTo,
    setSendTo,
    sendAmount,
    setSendAmount,
    sendHubFeePayer,
    setSendHubFeePayer,
    sendForceL1,
    setSendForceL1,
    preview,
    setPreview,
    payScanMode,
    setPayScanMode,
    sendOptions,
    syncSendPrefsFromSettings,
    persistSendPrefs,
    loadPaymentPayload,
    handlePreviewSend,
    handleConfirmSend,
    goToPayContact,
    resetPreview,
    busy,
  };
}