import { useCallback, useState } from "react";
import { api, type BtcSendPreview } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { isValidHacashAddress } from "../paymentQr";
import { authorizePreparedOperation } from "../preparedAuthorization";

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
    if (!isValidHacashAddress(to)) {
      onNotify("Enter a valid Hacash recipient address.", "error");
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
      const status = await api.status();
      const inspected = await api.inspectAddress(to, status.network_mode);
      if (!inspected.network_allowed) {
        throw new Error(inspected.warning || "This address is not enabled on the selected network");
      }
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
    setBusy(true);
    try {
      const prepared = await api.prepareSendBtc(preview.to, preview.satoshi);
      await authorizePreparedOperation(prepared, nativeBioAvailable);
      const result = await api.executePreparedBtc(prepared.id);
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
