import { useCallback, useState } from "react";
import { api, type BtcSendPreview, type PlatformSecurityStatus, type WalletSettings } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { hapticSuccess } from "../utils/haptic";
import { maybeWebAuthnGate } from "../utils/webauthnGate";

export function useBtcSend(opts: {
  active: boolean;
  settings: WalletSettings | null;
  platformSec: PlatformSecurityStatus | null;
  setBusy: (b: boolean) => void;
  refresh: () => Promise<void>;
  showToast: (msg: string, kind: "success" | "info" | "error") => void;
}) {
  const { active, settings, platformSec, setBusy, refresh, showToast } = opts;
  const [recipient, setRecipient] = useState("");
  const [btcAmount, setBtcAmount] = useState("");
  const [preview, setPreview] = useState<BtcSendPreview | null>(null);

  const resetPreview = useCallback(() => setPreview(null), []);

  const handlePreview = useCallback(async () => {
    const to = recipient.trim();
    const btc = Number(btcAmount);
    if (!to.startsWith("1")) {
      showToast("Enter a valid Hacash recipient address (1…).", "error");
      return;
    }
    if (!Number.isFinite(btc) || btc <= 0) {
      showToast("Enter a positive BTC amount.", "error");
      return;
    }
    const satoshi = Math.round(btc * 100_000_000);
    setBusy(true);
    setPreview(null);
    try {
      const p = await api.previewSendBtc(to, satoshi);
      setPreview(p);
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [recipient, btcAmount, setBusy, showToast]);

  const handleConfirm = useCallback(async () => {
    if (!preview) return;
    try {
      await maybeWebAuthnGate({
        amountMei: preview.fee_mei,
        securityProfile: settings?.security_profile,
        webauthnEnabled: settings?.webauthn_enabled,
        nativeBiometricAvailable: platformSec?.native_biometric_available,
      });
    } catch (e) {
      showToast(formatInvokeError(e), "error");
      return;
    }
    setBusy(true);
    try {
      const result = await api.sendBtc(preview.to, preview.satoshi);
      setPreview(null);
      setRecipient("");
      setBtcAmount("");
      showToast(`BTC sent on chain (${result.rail})`, "success");
      hapticSuccess();
      await refresh();
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [platformSec, preview, refresh, setBusy, settings, showToast]);

  return {
    recipient,
    setRecipient,
    btcAmount,
    setBtcAmount,
    preview,
    resetPreview,
    handlePreview,
    handleConfirm,
    active,
  };
}