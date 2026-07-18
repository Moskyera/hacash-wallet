import { useCallback, useState } from "react";
import { api, type BtcSendPreview } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { runWebAuthnAuth, webAuthnClientOrigin } from "../webauthn";

export function useBtcSend(opts: {
  active: boolean;
  nativeBioAvailable: boolean;
  setBusy: (b: boolean) => void;
  onNotify: (msg: string, kind: "success" | "info" | "error") => void;
  onSent: () => Promise<void>;
}) {
  const { active, nativeBioAvailable, setBusy, onNotify, onSent } = opts;
  const [recipient, setRecipient] = useState("");
  const [btcAmount, setBtcAmount] = useState("");
  const [preview, setPreview] = useState<BtcSendPreview | null>(null);

  const resetPreview = useCallback(() => setPreview(null), []);

  const handlePreview = useCallback(async () => {
    const to = recipient.trim();
    const btc = Number(btcAmount);
    if (!to.startsWith("1")) {
      onNotify("Enter a valid Hacash recipient address (1…).", "error");
      return;
    }
    if (!Number.isFinite(btc) || btc <= 0) {
      onNotify("Enter a positive BTC amount.", "error");
      return;
    }
    const satoshi = Math.round(btc * 100_000_000);
    setBusy(true);
    setPreview(null);
    try {
      const p = await api.previewSendBtc(to, satoshi);
      setPreview(p);
    } catch (e) {
      onNotify(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [recipient, btcAmount, setBusy, onNotify]);

  const handleConfirm = useCallback(async () => {
    if (!preview) return;
    try {
      const status = await api.status();
      if (status.webauthn_enabled) {
        const options = await api.webauthnAuthBegin(webAuthnClientOrigin());
        const assertion = await runWebAuthnAuth(options);
        await api.webauthnAuthFinish(assertion);
      } else if (nativeBioAvailable) {
        await api.confirmBiometricNative();
      } else {
        throw new Error("Enable WebAuthn or Windows Hello before sending bridged BTC");
      }
    } catch (e) {
      onNotify(formatInvokeError(e), "error");
      return;
    }
    setBusy(true);
    try {
      const result = await api.sendBtc(preview.to, preview.satoshi);
      setPreview(null);
      setRecipient("");
      setBtcAmount("");
      onNotify(`BTC on Hacash transaction submitted (${result.rail})`, "success");
      await onSent();
    } catch (e) {
      onNotify(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [nativeBioAvailable, preview, onSent, setBusy, onNotify]);

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
